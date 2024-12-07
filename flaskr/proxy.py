import os
from mitmproxy import http
import traceback
import string
import random

import sys
sys.path.append("..")  # Adds higher directory to python modules path. (Do not use .. in import)
from implementation import utils
from implementation.encryption import aes, salsa
from implementation.authentication import mac as mac_file
from datetime import datetime



# Check if the errors directory exists
if not os.path.exists('errors'):
    os.mkdir('errors')

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! #
# DO NOT ADD ANY CODE OUTSIDE THE REQUEST AND RESPONSE FUNCTIONS #
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! #


def request(flow: http.HTTPFlow) -> None:
    try:
        if 'http://cns_flaskr/' != flow.request.url[:18]:  # Checks if the traffic is meant for the flaskr website
            return
        flow.comment = 'cns_flaskr'  # Somehow indicate the flow is about traffic from cns_flaskr
        # read config of flaskr
        key = utils.get_preshared_key()
        config = utils.read_config_flaskr()
        accept_encodings = config["encryption"]["methods"]
        accept_macs = config["mac"]["methods"]
        accept_macs_str = ",".join(accept_macs)
        if flow.request.headers.get("Authorization", ""):
            header_value = flow.request.headers["Authorization"]
        else:
            header_value = ""
        # Split by spaces to get the auth method and rest of the string
        parts = header_value.split(" ", 1)
        auth_method = parts[0]

        # check if auth method is supported by the flaskr
        if auth_method not in accept_macs:
            flow.response = http.Response.make(401, b"Not authorized", {"Content-Type": "text/html",
                                                                        "date": datetime.now().strftime(
                                                                            "%a, %d %b %Y %H:%M:%S %Z"),
                                                                        "connection": "close",
                                                                        "WWW-Authenticate": accept_macs_str})
            return

        def authorize():
            # Now split the remaining part by commas to get each key-value pair
            key_value_pairs = parts[1].split(", ")

            # Extract nonce and mac
            auth_nonce = key_value_pairs[1].split("=")[1].strip('"')
            mac = key_value_pairs[3].split("=")[1].strip('"')

            # replace mac with empty string
            auth_header = flow.request.headers.get("Authorization", "")
            header_parts = auth_header.split(', ')
            header_parts = [part for part in header_parts if not part.startswith('mac=')]
            header_value_without_mac = ', '.join(header_parts)
            flow.request.headers["Authorization"] = header_value_without_mac

            # calculate time diff between the client and server
            request_timestamp = int(flow.request.headers["X-Authorization-Timestamp"])
            current_time = int(datetime.now().timestamp())
            diff_time = int(current_time) - int(request_timestamp)

            # if it differs more than 900 seconds the request will be rejected
            if diff_time > 900:
                flow.response = http.Response.make(401, b"Not authorized", {"Content-Type": "text/html",
                                                                            "date": datetime.now().strftime(
                                                                                "%a, %d %b %Y %H:%M:%S %Z"),
                                                                            "connection": "close",
                                                                            "WWW-Authenticate": accept_macs_str})
                return

            # mac the request
            string_to_auth = mac_file.get_string_to_auth(flow.request)
            new_mac = ""
            if auth_method == "sha1":
                new_mac = mac_file.generate_mac_sha1(string_to_auth, key, auth_nonce.encode())
            elif auth_method == "sha512hmac":
                new_mac = mac_file.generate_mac_hmac(string_to_auth, key, auth_nonce.encode())

            # If the content is not the same as the request we do not authorize it
            if mac != new_mac:
                flow.response = http.Response.make(401, b"Not authorized", {"Content-Type": "text/html",
                                                                            "date": datetime.now().strftime(
                                                                                "%a, %d %b %Y %H:%M:%S %Z"),
                                                                            "connection": "close",
                                                                            "WWW-Authenticate": accept_macs_str})
                return

        # if auth method is sha512hmac authorize first and then decrypt
        if auth_method == "sha512hmac":
            authorize()

        # Check if the Encryption header is present
        if 'Encryption' in flow.request.headers:
            # get the nonce
            header_value = flow.request.headers['Encryption']  # Your original string
            nonce = header_value.split('nonce="')[1].split('"')[0]
            # get the encryption method of the client
            encryption_method = flow.request.headers["Content-Encoding"]
            # check if the encryption method is supported by the flaskr
            if encryption_method not in accept_encodings:
                flow.response = http.Response.make(
                    400,
                    "Not a valid encoding method",
                    {"Known-Methods": ", ".join(accept_encodings)}
                )
                return
            else:
                if encryption_method == 'aes256cbc' and len(flow.request.raw_content) % 16 == 0:
                    # Decrypt response content using the AES implementation
                    flow.request.raw_content = aes.decrypt(flow.request.raw_content, key, nonce.encode())
                elif encryption_method == 'salsa20':
                    # Decrypt response content using the SALSA implementation
                    flow.request.raw_content = salsa.decrypt(flow.request.raw_content, key, nonce.encode())
            flow.request.headers['Content-Length'] = str(len(flow.request.raw_content))  # Update content length
            # delete the headers if we have done the decryption
            del flow.request.headers['Encryption']
            del flow.request.headers["Content-Encoding"]

        # if auth method is sha1 decrypt first and then authorize
        if auth_method == "sha1":
            authorize()


        # If the traffic is meant for the flaskr website, redirect it to the webserver (reverse proxy)
        flow.request.host = 'localhost'  # Important do not delete
        flow.request.port = 5000

        # remove any non-printable characters from message body
        if len(flow.request.raw_content) > 0:
            allowed = set(range(32, 127)).union({9, 10, 13})
            flow.request.raw_content = bytes([b for b in flow.request.raw_content if b in allowed])
            flow.request.headers['Content-Length'] = str(len(flow.request.raw_content))

    except Exception as e:
        # Return an error reply to the client with the error message
        utils.write_error(flow, 'Server side - Request:\n{}\n{}'.format(e, traceback.format_exc()))
        # Do not let the message go through to the website, nor the reverse proxy. Direct to random port
        flow.request.port = 5003


def response(flow: http.HTTPFlow) -> None:
    # If the response is an error message, return the message without performing any actions
    if flow.response.status_code >= 400:
        return
    try:
        if 'cns_flaskr' not in flow.comment:  # Checks if the traffic is meant for the flaskr website
            return

        def generate_random_nonce(length=16) -> str:
            """Generate a random nonce string of a specified length."""
            characters = string.ascii_letters + string.digits  # Letters and digits
            return ''.join(random.choice(characters) for _ in range(length))

        # read config of flaskr
        config = utils.read_config_flaskr()
        key_id = config['encryption']['keyid']
        key = utils.get_preshared_key()
        accept_encodings = config["encryption"]["methods"]
        nonce = generate_random_nonce()
        header_value_req = flow.request.headers["Authorization"]
        # Split by spaces to get the auth method and rest of the string
        parts = header_value_req.split(" ", 1)
        auth_method = parts[0]

        def authenticate(method, auth_key, auth_nonce):
            flow.response.headers["Authorization"] = ""
            flow.response.headers["X-Authorization-Timestamp"] = str(int(datetime.now().timestamp()))
            header_names = sorted(flow.response.headers.keys())
            header_names_str = ";".join(header_names)
            temp_header_value = '{} keyid="{}", nonce="{}", headers="{}"'.format(method, key_id, auth_nonce,
                                                                                           header_names_str)
            flow.response.headers["Authorization"] = temp_header_value
            string_to_auth = mac_file.get_string_to_auth(flow.response)
            mac = ""
            if method == "sha1":
                mac = mac_file.generate_mac_sha1(string_to_auth, auth_key, auth_nonce.encode())
            elif method == "sha512hmac":
                mac = mac_file.generate_mac_hmac(string_to_auth, auth_key, auth_nonce.encode())

            header_value = '{} keyid="{}", nonce="{}", headers="{}", mac="{}"'.format(method, key_id, auth_nonce,
                                                                                      header_names_str, mac)
            flow.response.headers["Authorization"] = header_value

        # get the encryption method of the client
        if flow.request.headers.get("Accept-Encoding", ""):
            temp_encoding = flow.request.headers["Accept-Encoding"]
        else:
            temp_encoding = ""
        accepted_encodings = [encoding.strip() for encoding in temp_encoding.split(",")]
        encryption_method = accepted_encodings[-1]

        if auth_method != "sha1" and auth_method != "sha512hmac":
            authenticate(auth_method, key_id, nonce)

        # Authenticate first and then encrypt if the method is sha1
        if auth_method == "sha1":
            authenticate("sha1", key, nonce)

        # Encryption if there is content
        if int(flow.response.headers.get('Content-Length', 0)) > 0:
            flow.response.headers["Content-Encoding"] = encryption_method
            # check if the encryption method is supported by the flaskr
            if encryption_method not in accept_encodings:
                flow.response = http.Response.make(
                    400,
                    "Not a valid encoding method",
                    {"Known-Methods": ", ".join(accept_encodings)}
                )
                return
            # Encrypt the request content depending on the used method
            encrypted_content = ""
            if encryption_method == 'aes256cbc':
                encrypted_content = aes.encrypt(flow.response.raw_content, key, nonce.encode())
            elif encryption_method == 'salsa20':
                encrypted_content = salsa.encrypt(flow.response.raw_content, key, nonce.encode())

            # Set the headers for encryption
            if encryption_method == "aes256cbc" or encryption_method == "salsa20":
                flow.response.headers["Encryption"] = 'keyid="{}", nonce="{}"'.format(key_id, nonce)
                flow.response.raw_content = encrypted_content
                flow.response.headers['Content-Length'] = str(len(flow.response.raw_content))  # Update content length

        # Encrypt first and then authenticate if method is sha512hmac
        if auth_method == "sha512hmac":
            authenticate("sha512hmac", key, nonce)




    except Exception as e:
        # Return an error reply to the client with the error message
        utils.write_error(flow, 'Server side - Response:\n{}\n{}'.format(e, traceback.format_exc()))
