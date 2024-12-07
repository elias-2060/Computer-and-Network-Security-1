import os
import traceback
from mitmproxy import http
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
    try:  # Do not edit this line
        if 'http://cns_flaskr/' != flow.request.url[:18]:  # Checks if the traffic is meant for the flaskr website
            return
        flow.comment = 'cns_flaskr'  # Somehow indicate the flow is about traffic from cns_flaskr

        def generate_random_nonce(length=16) -> str:
            """Generate a random nonce string of a specified length."""
            characters = string.ascii_letters + string.digits  # Letters and digits
            return ''.join(random.choice(characters) for _ in range(length))

        def authenticate(method, auth_key, auth_nonce):
            flow.request.headers["Authorization"] = ""
            flow.request.headers["X-Authorization-Timestamp"] = str(int(datetime.now().timestamp()))
            header_names = sorted(flow.request.headers.keys())
            header_names_str = ";".join(header_names)
            # add authorization header before the string_to_auth without mac
            temp_header_value = '{} keyid="{}", nonce="{}", headers="{}"'.format(method, key_id, auth_nonce, header_names_str)
            flow.request.headers["Authorization"] = temp_header_value
            string_to_auth = mac_file.get_string_to_auth(flow.request)
            mac = ""
            if method == "sha1":
                mac = mac_file.generate_mac_sha1(string_to_auth, auth_key, auth_nonce.encode())
            elif method == "sha512hmac":
                mac = mac_file.generate_mac_hmac(string_to_auth, auth_key, auth_nonce.encode())

            # add the mac in the authorization header
            header_value = '{} keyid="{}", nonce="{}", headers="{}", mac="{}"'.format(method, key_id, auth_nonce,
                                                                                      header_names_str, mac)
            flow.request.headers["Authorization"] = header_value

        # read from the config
        config = utils.read_config_client()
        key_id = config['encryption']['keyid']
        key = utils.get_preshared_key()
        # Generate a new random nonce
        nonce = generate_random_nonce()
        auth_method = config['mac']['method']
        encrypt_method = config['encryption']['method']
        # update the accept encoding with the method of the client
        temp = flow.request.headers["Accept-Encoding"]
        flow.request.headers["Accept-Encoding"] = temp + ", " + encrypt_method

        if auth_method != "sha1" and auth_method != "sha512hmac":
            authenticate(auth_method, key, nonce)

        # Authenticate first and then encrypt if the method is sha1
        if auth_method == "sha1":
            authenticate("sha1", key, nonce)


        # Encryption if there is content
        if int(flow.request.headers.get('Content-Length', 0)) > 0:
            flow.request.headers["Content-Encoding"] = encrypt_method
            # Encrypt the request content depending on the method
            encrypted_content = ""
            if encrypt_method == "aes256cbc":
                encrypted_content = aes.encrypt(flow.request.raw_content, key, nonce.encode())
            elif encrypt_method == "salsa20":
                encrypted_content = salsa.encrypt(flow.request.raw_content, key, nonce.encode())


            # Add the encryption header if we encrypted
            if encrypt_method == "aes256cbc" or encrypt_method == "salsa20":
                flow.request.headers["Encryption"] = 'keyid="{}", nonce="{}"'.format(key_id, nonce)
                flow.request.raw_content = encrypted_content
                flow.request.headers['Content-Length'] = str(len(flow.request.raw_content))  # Update content length


        # Encrypt first and then authenticate if method is sha512hmac
        if auth_method == "sha512hmac":
            authenticate("sha512hmac", key, nonce)

    except Exception as e:
        # Return an error reply to the client with the error message
        utils.write_error(flow, 'Client side - Request:\n{}\n{}'.format(e, traceback.format_exc()))


def response(flow: http.HTTPFlow) -> None:
    # If the response is an error message, return the message without performing any actions
    if flow.response.status_code >= 400:
        return
    try:
        if 'cns_flaskr' not in flow.comment:  # Checks if the traffic is meant for the flaskr website
            return

        key = utils.get_preshared_key()
        if flow.response.headers.get("Authorization", ""):
            header_value = flow.response.headers["Authorization"]
        else:
            header_value = ""
        # Split by spaces to get the auth method and rest of the string
        parts = header_value.split(" ", 1)
        auth_method = parts[0]

        def authorize():
            # Now split the remaining part by commas to get each key-value pair
            key_value_pairs = parts[1].split(", ")

            # Extract nonce and mac
            auth_nonce = key_value_pairs[1].split("=")[1].strip('"')
            mac = key_value_pairs[3].split("=")[1].strip('"')

            # replace mac with empty string
            if flow.response.headers.get("Authorization", ""):
                auth_header = flow.response.headers.get("Authorization", "")
            else:
                auth_header = ""
            header_parts = auth_header.split(', ')
            header_parts = [part for part in header_parts if not part.startswith('mac=')]
            header_value_without_mac = ', '.join(header_parts)
            flow.response.headers["Authorization"] = header_value_without_mac

            # calculate time diff between the client and server
            if flow.response.headers.get("X-Authorization-Timestamp", ""):
                request_timestamp = int(flow.response.headers["X-Authorization-Timestamp"])
            else:
                request_timestamp= 0
            current_time = int(datetime.now().timestamp())
            diff_time = int(current_time) - int(request_timestamp)

            # if it differs more than 900 seconds the response will be rejected
            if diff_time > 900:
                flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/html",
                                                                                            "date": datetime.now().strftime(
                                                                                                "%a, %d %b %Y %H:%M:%S %Z"),
                                                                                            "connection": "close",
                                                                                            "WWW-Authenticate": auth_method})
                return

            # mac the response
            string_to_auth = mac_file.get_string_to_auth(flow.response)
            if auth_method == "sha1":
                new_mac = mac_file.generate_mac_sha1(string_to_auth, key, auth_nonce.encode())
            elif auth_method == "sha512hmac":
                new_mac = mac_file.generate_mac_hmac(string_to_auth, key, auth_nonce.encode())
            else:
                flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/html",
                                                                                            "date": datetime.now().strftime(
                                                                                                "%a, %d %b %Y %H:%M:%S %Z"),
                                                                                            "connection": "close",
                                                                                            "WWW-Authenticate": auth_method})
                return

            # If the content is not the same as the response we do not authorize it
            if mac != new_mac:
                flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/html",
                                                                                            "date": datetime.now().strftime(
                                                                                                "%a, %d %b %Y %H:%M:%S %Z"),
                                                                                            "connection": "close",
                                                                                            "WWW-Authenticate": auth_method})
                return

        # if auth method is sha512hmac authorize first and then decrypt
        if auth_method == "sha512hmac":
            authorize()
        elif auth_method == "sha1":
            pass
        else:
            flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/html",
                                                                                        "date": datetime.now().strftime(
                                                                                            "%a, %d %b %Y %H:%M:%S %Z"),
                                                                                        "connection": "close",
                                                                                        "WWW-Authenticate": auth_method})
            return


        # Check if the Encryption header is present
        if 'Encryption' in flow.response.headers:
            # get the nonce
            header_value = flow.response.headers['Encryption']  # Your original string
            nonce = header_value.split('nonce="')[1].split('"')[0]
            # get the encryption method
            encryption_method = flow.response.headers["Content-Encoding"]
            # Check if it has the correct size and method is correct
            if encryption_method == 'aes256cbc' and len(flow.response.raw_content) % 16 == 0:
                # Decrypt response content using the AES implementation
                flow.response.raw_content = aes.decrypt(flow.response.raw_content, key, nonce.encode())
            elif encryption_method == 'salsa20':
                # Decrypt response content using the SALSA implementation
                flow.response.raw_content = salsa.decrypt(flow.response.raw_content, key, nonce.encode())
            # Update content length
            flow.response.headers['Content-Length'] = str(len(flow.response.raw_content))
            # delete the encryption and content encoding headers after decryption
            del flow.response.headers['Encryption']
            del flow.response.headers["Content-Encoding"]

        # if auth method is sha1 decrypt first and then authorize
        if auth_method == "sha1":
            authorize()
        elif auth_method == "sha512hmac":
            pass
        else:
            flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/html",
                                                                                        "date": datetime.now().strftime(
                                                                                            "%a, %d %b %Y %H:%M:%S %Z"),
                                                                                        "connection": "close",
                                                                                        "WWW-Authenticate": auth_method})
            return


    except Exception as e:
        # Return an error reply to the client with the error message
        utils.write_error(flow, 'Client side - Response:\n{}\n{}'.format(e, traceback.format_exc()))