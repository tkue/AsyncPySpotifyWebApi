import asyncio
import copy
import time
from os import environ
import requests
import json
from enum import Enum
from functools import cache
from dataclasses import dataclass, field
import asyncio
import aiohttp
from abc import abstractmethod
from urllib.parse import urlparse, parse_qs, urlsplit, urlunsplit, urlencode, quote
from requests.models import PreparedRequest, Response
from auth_helper import load_env
from urllib.parse import urljoin
from requests_oauthlib import OAuth2Session

import requests
from urllib.parse import urlencode
import base64
import webbrowser

from spotify_auth import write_env_file, EnvFileTypes

# TODO: document/docstrings

class ApiMethodType(Enum):
    GET = 'get'
    POST = 'post'
    PUT = 'put'
    DELETE = 'delete'


class SpotifyScopeTypes(Enum):
    # Images
    UGC_IMAGE_UPLOAD = 'ugc-image-upload'

    # Spotify Connect
    USER_READ_PLAYBACK_STATE = 'user-read-playback-state'
    USER_MODIFY_PLAYBACK_STATE = 'user-modify-playback-state'
    USER_READ_CURRENTLY_PLAYING = 'user-read-currently-playing'

    # Playback
    APP_REMOTE_CONTROL = 'app-remote-control'
    STREAMING = 'streaming'

    # Playlists
    PLAYLIST_READ_PRIVATE = 'playlist-read-private'
    PLAYLIST_READ_COLLABORATIVE = 'playlist-read-collaborative'
    PLAYLIST_MODIFY_PRIVATE = 'playlist-modify-private'
    PLAYLIST_MODIFY_PUBLIC = 'playlist-modify-public'

    # Follow
    USER_FOLLOW_MODIFY = 'user-follow-modify'
    USER_FOLLOW_READ = 'user-follow-read'

    # Listening History
    USER_READ_PLAYBACK_POSITION = 'user-read-playback-position'
    USER_TOP_READ = 'user-top-read'
    USER_READ_RECENTLY_PLAYED = 'user-read-recently-played'

    # Library
    USER_LIBRARY_MODIFY = 'user-library-modify'
    USER_LIBRARY_READ = 'user-library-read'

    # Users
    USER_READ_EMAIL = 'user-read-email'
    USER_READ_PRIVATE = 'user-read-private'

    # Open Access
    USER_SOA_LINK = 'user-soa-link'
    USER_SOA_UNLINK = 'user-soa-unlink'
    SOA_MANAGE_ENTITLEMENTS = 'soa-manage-entitlements'
    SOA_MANAGE_PARTNER = 'soa-manage-partner'
    SOA_CREATE_PARTNER = 'soa-create-partner'

@dataclass
class ApiCall:
    url: str = field(init=True)
    method: ApiMethodType = field(init=True)
    payload: dict = field(init=False)
    response: dict|str = field(init=False, repr=False, hash=False)
    response_object_type: str = field(init=False)  # to keep track of the object we are expecting to be returned
    number_of_attempts: int = field(init=False, default=0)  # if we want to retry, we can increment a counter here

    def __init__(self, url, method, payload={}, response_object_type=None):
        self.url = url
        self.method = method
        self.payload = payload
        if response_object_type:
            self.response_object_type = response_object_type

    def copy_with_new_url(self, new_url: str):
        new_api_call =  copy.deepcopy(self)
        new_api_call.url = new_url
        return new_api_call

    @property
    def api_url_path(self):
        parsed_url = urlparse(self.url)
        return parsed_url.path

# TODO: Might be good to refactor into it's own package
class ApiSession(object):
    def __init__(self, n_workers: int, base_url: str, max_retries: int=0, retry_delay: int=1):
        self.n_workers = n_workers
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._base_url = base_url

    async def _worker(self, queue: asyncio.Queue, session: aiohttp.ClientSession, results: [ApiCall]):
        while True:
            api_call = await queue.get()
            if not api_call:
                break

            r = await session.request(method=api_call.method.value, url=api_call.url, params=api_call.payload)
            api_call.response = await r.json()
            api_call.number_of_attempts += 1

            # TODO: implement retries
            # if api_call.response.status not in [200, 201]

            results.append(api_call)
            queue.task_done()

    async def _make_api_calls(self, api_calls: [ApiCall], headers: {}=None, session: aiohttp.ClientSession=None):
        queue = asyncio.Queue(self.n_workers)
        results = []

        if not session:
            session = aiohttp.ClientSession(headers=headers)

        workers = [asyncio.create_task(self._worker(queue, session, results))
                   for _ in range(self.n_workers)]

        for api_call in api_calls:
            await queue.put(api_call)
            await asyncio.sleep(0)

        await queue.join()

        queue.empty()

        for worker in workers:
            worker.cancel()

        return results

    def _get_url(self, path: str, *args):
        return urljoin(self._base_url, path.format(*args))


    @abstractmethod
    def get_headers(self):
        raise NotImplementedError()

    @staticmethod
    def add_params_to_url_request(url, params):
        req = PreparedRequest()
        req.prepare_url(url, params)
        return req.url

class SpotifyUrl(Enum):
    HEADER = {'Content-Type': 'application/x-www-form-urlencoded'}
    GET_TOKEN = 'https://accounts.spotify.com/api/token'

class SpotifySession(ApiSession):
    __HEADER_TOKEN = {'Content-Type': 'application/x-www-form-urlencoded'}
    __API_RETURN_ITEM_LIMIT = 50
    __DEFAULT_SPOTIFY_BASE_URL = 'https://api.spotify.com/v1/'

    def __init__(self, client_id, client_secret, redirect_uri, oauth_access_token_json: str, scopes: [SpotifyScopeTypes], limit=20,
                 n_workers: int = 1, max_retries: int = 0, retry_delay: int = 1, spotify_base_url: str = None):
        self.__client_id = client_id
        self.__client_secret = client_secret
        self.__oauth_access_token = OauthAccessToken(oauth_access_token_json)
        self.__user_oauth_access_token_value = self.__oauth_access_token.access_token
        self.__scopes = scopes
        self.__redirect_uri = redirect_uri
        if spotify_base_url:
            self.__spotify_base_url = spotify_base_url
        else:
            self.__spotify_base_url = SpotifySession.__DEFAULT_SPOTIFY_BASE_URL

        if limit > SpotifySession.__API_RETURN_ITEM_LIMIT:
            raise ValueError('Limit can be a maximum of {}, but you gave {}'.format(self.__API_RETURN_ITEM_LIMIT, limit))

        self.__limit = limit

        super().__init__(n_workers=n_workers, base_url=self.__spotify_base_url, max_retries=max_retries, retry_delay=retry_delay)

        self.__access_token = None

    def __make_api_call(self, method, url, header, payload=None, token_function=None):
        is_retry_token = False

        r = requests.request(method, url, headers=header, data=payload)
        if r.status_code != 200:
            if r.status_code == 401 and token_function and not is_retry_token:
                # TODO: move to base class
                try:
                    token_function()
                    is_retry_token = True
                    self.__make_api_call(method, url, header, payload, token_function)
                except:
                    raise


            raise requests.RequestException('Failed to make API call. Response code: {0}'.format(r.status_code))

        return r

    def __get_access_token(self):
        # TODO: refactor
        url = 'https://accounts.spotify.com/api/token'

        header = self.__HEADER_TOKEN
        payload = 'grant_type=client_credentials&client_id={0}&client_secret={1}'.format(self.__client_id, self.__client_secret)

        r = self.__make_api_call('POST', url, header, payload)
        return AccessToken(r)

    async def _make_api_calls(self, api_calls: [ApiCall], headers: {}=None, is_get_all: bool=False):
        # TODO: implement caching - e.g. don't want to make the same call for a song because it is in more than one playlist
        # TODO: refactor and allow to pass in session
        session = aiohttp.ClientSession(headers=headers)

        try:
            api_call_return = await super()._make_api_calls(api_calls=api_calls, headers=headers, session=session)

            # get all api result pages
            if is_get_all:
                processed_paths = []
                additional_api_calls_to_process = []

                for api_call in api_calls:
                    if not api_call.response:
                        continue

                    api_response = JsonResponse.from_api_call(api_call)

                    # we only need to process a given path once
                    if api_response.api_url_path in processed_paths:
                        continue

                    # create a copy of the original api call object, but this time with a new URL
                    for additional_url in api_response.get_remaining_urls():
                        additional_api_calls_to_process.append(api_call.copy_with_new_url(new_url=additional_url))

                    # record we processed this path already
                    processed_paths.append(api_response.api_url_path)
                new_api_results = await super()._make_api_calls(api_calls=additional_api_calls_to_process, headers=headers, session=session)
                api_call_return += new_api_results
        except Exception:
            raise
        finally:
            await session.close()


        return api_call_return


    @property
    def access_token(self):
        if not self.__access_token:
            self.__access_token = self.__get_access_token().access_token

        return self.__access_token

    def _add_params_to_url_request(self, url, offset: int=0):
        params = {'offset': offset, 'limit': self.__limit}
        return ApiSession.add_params_to_url_request(url, params)

    def get_headers(self):
        return {'Authorization': 'Bearer {}'.format(self.access_token)}

    def get_headers_oauth(self):
        return {'Authorization': 'Bearer {}'.
        format(self.__user_oauth_access_token_value)}

    def __get_oauth_token(self):
        # TODO: can we make this more seamless or do we always need to user to copy/paste?

        # TODO: refactor URl's
        authorization_base_url = "https://accounts.spotify.com/authorize"
        token_url = "https://accounts.spotify.com/api/token"

        scope = [x.value for x in self.__scopes]
        spotify = OAuth2Session(client_id, scope=scope, redirect_uri=redirect_uri)
        authorization_url, state = spotify.authorization_url(authorization_base_url)
        webbrowser.open_new_tab(authorization_url)

        redirect_response = input('\n\nPaste the full redirect URL here: ')

        from requests.auth import HTTPBasicAuth
        auth = HTTPBasicAuth(self.__client_id, self.__client_secret)
        token = spotify.fetch_token(token_url, auth=auth,
                                    authorization_response=redirect_response)


        write_env_file(EnvFileTypes.OAUTH_ACCESS_TOKEN_JSON.value, json.dumps(token))


        return token

    def get_playlists(self, is_get_all=False, user_id: str=None):
        if not user_id:
            url = self._get_url('me/playlists')  # TODO: this one is pretty useless: it seems to give test data...
        else:
            url = self._get_url('users/{0}/playlists', user_id)

        url = self._add_params_to_url_request(url, offset=0)
        header = self.get_headers()
        api_call = ApiCall(url=url, method=ApiMethodType.GET)
        api_results = asyncio.run(self._make_api_calls([api_call,], headers=header, is_get_all=is_get_all))

        for result in [JsonResponse.from_api_call(api_results) for api_results in api_results]:
            for item in result.iter_items():
                yield Playlist(item)

    def get_user(self):
        # TODO: Check to see if need new token (check expiration)
        url = self._get_url('me')
        header = self.get_headers_oauth()
        r = self.__make_api_call(method='get', url=url, header=header, token_function=self.__get_oauth_token)
        return User(r.text)



class JsonResponse(object):
    def __init__(self, response: dict|str|aiohttp.ClientResponse|requests.Response):
        self.response = response

    @classmethod
    def from_api_call(cls, api_call: ApiCall):
        return cls(api_call.response)

    @property
    def limit(self):
        return self.response.get('limit')

    @property
    def total(self):
        return self.response.get('total')

    @property
    def offset(self):
        return self.response.get('offset')

    @property
    def next_href(self):
        return self.response.get('next')

    @property
    def href(self):
        return self.response.get('href')

    @property
    def api_url_path(self):
        parsed_url = urlparse(self.href)
        return parsed_url.path

    def get_remaining_urls(self):
        return JsonResponse.get_additional_urls(url=self.href, total_items=self.total)

    @staticmethod
    def get_additional_urls(url: str, total_items: int):
        parsed_url = urlparse(url)

        url_query_parts = parse_qs(parsed_url.query)
        url_offset = int(url_query_parts["offset"][0])
        url_limit = int(url_query_parts["limit"][0])

        additional_urls = []

        while url_offset + url_limit < total_items:
            url_offset += url_limit
            split = urlsplit(url)
            url = urlunsplit((
                split.scheme,
                split.netloc,
                split.path,
                urlencode({'offset': url_offset, 'limit': url_limit}),
                None
            ))

            additional_urls.append(url)

        return additional_urls

    @staticmethod
    def get_additional_urls_from_response(response: str):
        return JsonResponse.get_additional_urls(url=response['href'], total_items=int(response['total']))

    def get_json_response_dump(self):
        indent = 4
        if isinstance(self.response, dict) or isinstance(self.response, str):
            return json.dumps(self.response, indent=indent)

        if isinstance(self.response, aiohttp.ClientResponse) or isinstance(self.response, requests.Response):
            return json.dumps(self.response.json(), indent=indent)

    def get_json_response(self):
        if isinstance(self.response, str):
            return json.loads(self.response)
        if isinstance(self.response, dict):
            return self.response

        if isinstance(self.response, aiohttp.ClientResponse) or isinstance(self.response, requests.Response):
            return json.loads(self.response.text)

    def iter_items(self):
        for item in self.get_json_response()['items']:
            yield item


class AccessToken(JsonResponse):
    def __init__(self, response):
        super(AccessToken, self).__init__(response)

    @property
    def access_token(self):
        return self.get_json_response()['access_token']

    @property
    def token_type(self):
        return self.get_json_response()['token_type']

    @property
    def expires_in(self):
        return self.get_json_response()['expires_in']

    def is_token_expired(self):
        return self.expires_in < time.time()


class OauthAccessToken(AccessToken):
    def __init__(self, response):
        super(OauthAccessToken, self).__init__(response)

    @property
    def refresh_token(self):
        return self.get_json_response()['refresh_token']

    @property
    def scope(self):
        return self.get_json_response()['scope']

    @property
    def expires_at(self):
        return self.get_json_response()['expires_at']


class Playlist(JsonResponse):
    def __init__(self, response):
        super(Playlist, self).__init__(response)

    @property
    def name(self):
        return self.get_json_response()['name']

    @property
    def id(self):
        return self.get_json_response()['id']

    @property
    def number_of_tracks(self):
        return self.get_json_response()['tracks']['total']

class User(JsonResponse):
    def __init__(self, response):
        super(User, self).__init__(response)

    @property
    def id(self):
        return self.get_json_response()['id']

    @property
    def display_name(self):
        return self.get_json_response()['display_name']


if __name__ == '__main__':


    # TODO: move to own dir and get rid of this test code

    load_env()


    client_id = environ.get('CLIENT_ID')
    client_secret = environ.get('CLIENT_SECRET')
    redirect_uri = environ.get('REDIRECT_URI')
    user_oauth = environ.get('USER_OAUTH')
    oauth_access_token_json = environ.get('OAUTH_ACCESS_TOKEN_JSON')

    # print(oauth_access_token_json)
    # exit()

    scopes = [SpotifyScopeTypes.PLAYLIST_READ_PRIVATE,
              SpotifyScopeTypes.PLAYLIST_READ_COLLABORATIVE,
              SpotifyScopeTypes.PLAYLIST_MODIFY_PUBLIC,
              SpotifyScopeTypes.PLAYLIST_MODIFY_PRIVATE
              # SpotifyScopeTypes.USER_READ_PRIVATE,
              # SpotifyScopeTypes.USER_READ_EMAIL,
              # SpotifyScopeTypes.UGC_IMAGE_UPLOAD
              ]

    session = SpotifySession(client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri,
                             oauth_access_token_json=oauth_access_token_json, scopes=scopes, n_workers=10, limit=20)


    # session.get_oauth_token()
    # exit()

    user = session.get_user()
    playlists = session.get_playlists(is_get_all=True, user_id=user.id)
    for i, playlist in enumerate(playlists):
        print(i)
        print(playlist.name, playlist.number_of_tracks)



