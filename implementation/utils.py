import os
from mitmproxy import http
import json

def example_function():
    pass

def read_config_client():
    """Read and return the contents of config.json in client."""
    path = "config.json"
    try:
        with open(path, 'r') as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"The file at {path} was not found.")
    except json.JSONDecodeError:
        print("Error decoding JSON from the file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def read_config_flaskr():
    """Read and return the contents of config.json in flaskr."""
    path = "config.json"
    try:
        with open(path, 'r') as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"The file at {path} was not found.")
    except json.JSONDecodeError:
        print("Error decoding JSON from the file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def write_error(flow: http.HTTPFlow, error: str) -> None:
    i = 0
    while os.path.exists('errors/error_{}.txt'.format(i)):
        i += 1
    open('errors/error_{}.txt'.format(i), 'w').write(error)
    flow.comment = 'ERROR: {}'.format(error)
    flow.response = http.Response.make(500, flow.comment[7:])


def get_preshared_key() -> str:
    with open('../implementation/preshared_key.txt', 'r') as f:
        return f.read()
