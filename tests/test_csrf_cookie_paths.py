"""The CSRF cookies must honour their own configured path, when set and when cleared alike."""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyBare
from fastapi_jwt_harmony.base import JWTHarmonyBase
from fastapi_jwt_harmony.config import JWTHarmonyConfig
from tests.user_models import SimpleUser

ACCESS_CSRF_PATH = '/api/access-csrf'
REFRESH_CSRF_PATH = '/api/refresh-csrf'


@pytest.fixture
def client():
    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(
            secret_key='testing',
            token_location=frozenset({'cookies'}),
            access_cookie_path='/api/access',
            refresh_cookie_path='/api/refresh',
            access_csrf_cookie_path=ACCESS_CSRF_PATH,
            refresh_csrf_cookie_path=REFRESH_CSRF_PATH,
        ),
    )

    app = FastAPI()

    @app.get('/login')
    def login(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        user = SimpleUser(id='1')
        authorize.set_access_cookies(authorize.create_access_token(user_claims=user))
        authorize.set_refresh_cookies(authorize.create_refresh_token(user_claims=user))
        return {'msg': 'ok'}

    @app.get('/logout')
    def logout(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        authorize.unset_jwt_cookies()
        return {'msg': 'ok'}

    yield TestClient(app)

    JWTHarmonyBase._config = None
    JWTHarmonyBase._user_model_class = None
    JWTHarmonyBase._token_in_denylist_callback = None


def path_of(response, cookie_name):
    for header in response.headers.get_list('set-cookie'):
        if header.startswith(f'{cookie_name}='):
            for part in header.split(';'):
                key, _, value = part.strip().partition('=')
                if key.lower() == 'path':
                    return value
    return None


def test_the_access_csrf_cookie_uses_its_own_path(client):
    response = client.get('/login')

    assert path_of(response, 'csrf_access_token') == ACCESS_CSRF_PATH
    assert path_of(response, 'access_token_cookie') == '/api/access'


def test_the_refresh_csrf_cookie_uses_its_own_path(client):
    response = client.get('/login')

    assert path_of(response, 'csrf_refresh_token') == REFRESH_CSRF_PATH
    assert path_of(response, 'refresh_token_cookie') == '/api/refresh'


# A deletion whose path differs from the one it was set with is silently a no-op, so logging out
# would appear to work while the cookie survived.
def test_clearing_the_cookies_uses_the_same_paths_they_were_set_with(client):
    response = client.get('/logout')

    assert path_of(response, 'csrf_access_token') == ACCESS_CSRF_PATH
    assert path_of(response, 'csrf_refresh_token') == REFRESH_CSRF_PATH
    assert path_of(response, 'access_token_cookie') == '/api/access'
    assert path_of(response, 'refresh_token_cookie') == '/api/refresh'
