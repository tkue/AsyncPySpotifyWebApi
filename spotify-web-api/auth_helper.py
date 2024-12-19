from os import walk, environ
from os.path import  join, abspath, basename

import requests
from urllib.parse import urlencode
import base64
import webbrowser
from spotify_auth import write_env_file, EnvFileTypes


def load_env():
    for root, subdir, files in walk("."):
        for file in files:
            if not file.endswith(".env"):
                continue

            file = abspath(join(root, file))
            env_var_name = basename(file).split('.')[0].upper()
            with open(file, 'r') as f:
                env_var_value = f.readline().strip()

            environ[env_var_name] = env_var_value


load_env()

client_id = environ.get('CLIENT_ID')
client_secret = environ.get('CLIENT_SECRET')
redirect_uri = environ.get('REDIRECT_URI')       # should match the Spotify settings for this project

# get code
def get_auth_code():
    auth_headers = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "user-library-read"
    }

    webbrowser.open("https://accounts.spotify.com/authorize?" + urlencode(auth_headers))

# take the code from the step above and pass it in to get the token
def get_token(code: str):
    encoded_credentials = base64.b64encode(client_id.encode() + b':' + client_secret.encode()).decode("utf-8")

    token_headers = {
        "Authorization": "Basic " + encoded_credentials,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri
    }

    r = requests.post("https://accounts.spotify.com/api/token", data=token_data, headers=token_headers)
    token = r.json()["access_token"]
    return token



if __name__ == '__main__':
    load_env()

    client_id = environ.get('CLIENT_ID')
    client_secret = environ.get('CLIENT_SECRET')
    redirect_uri = environ.get('REDIRECT_URI')  # should match the Spotify settings for this project


    # get code and then give it to the method below
    # get_auth_code()
    # exit()

    print(get_token("AQCdUmZg0qfuYaiejQrcWCELEHvNCWTYW9qvEYFPQSHKZL2F5lPnC9WDjt30ENeAaw4l7wAmGPyc0zs3-OJkM1CS4GlI8mEIBgbdV0ISpHK0ShbdKBe6o2GL_df129sJtt210DpsOxUpxuocOLlxO6an2rNNntOAm3DoVY51udswP-hKnF_kk78VIggf"))
