from os import walk, environ
from os.path import  join, abspath, basename, exists as path_exists
from enum import Enum

# TODO: refactor with config and initialization
# TODO: remove user_uoath.env - that is just the token and we are now using the entire JSON in an object (get things like expiration date)

class EnvFileTypes(Enum):
    CLIENT_ID = 'client_id.env'
    CLIENT_SECRET = 'client_secret.env'
    OAUTH_ACCESS_TOKEN_JSON = 'oauth_access_token_json.env'
    REDIRECT_URI = 'redirect_uri.env'
    USER_OAUTH = 'user_oauth.env'

def iter_env_file_paths():
    for root, subdir, files in walk("."):
        for file in files:
            if not file.endswith(".env"):
                continue

            yield abspath(join(root, file))

def get_env_key_name(env_file_path: str):
    return basename(env_file_path).split('.')[0].upper()

def load_env():
    for file in iter_env_file_paths():

        env_var_name = get_env_key_name(file)
        with open(file, 'r') as f:
            env_var_value = f.readline().strip()

        environ[env_var_name] = env_var_value


def write_env_file(file_name: str, value: str):
    env_actual_path = ''
    if not path_exists(file_name):
        for file in iter_env_file_paths():
            if basename(file) == basename(file_name):
                env_actual_path = abspath(file)
    else:
        env_actual_path = abspath(file_name)

    if not env_actual_path:
        raise FileNotFoundError('Unable to find env file: {}'.format(file_name))

    with open(env_actual_path, 'w') as f:
        f.write(value)


    key_name = get_env_key_name(env_actual_path)
    environ[key_name] = value