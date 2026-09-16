"""A caller may name the cookie and its path per call, for an application that scopes cookies per request."""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyBare
from fastapi_jwt_harmony.base import JWTHarmonyBase
from fastapi_jwt_harmony.config import JWTHarmonyConfig
from tests.user_models import SimpleUser

TENANT_PATH = '/api/t/acme'
TENANT_DOMAIN = 'acme.example.com'
ACCESS_KEY = 'acme_access_token'
ACCESS_CSRF_KEY = 'acme_csrf_access'
REFRESH_KEY = 'acme_refresh_token'
REFRESH_CSRF_KEY = 'acme_csrf_refresh'


@pytest.fixture
def client():
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(secret_key='testing', token_location=frozenset({'cookies'})))

    app = FastAPI()

    @app.get('/login-scoped')
    def login_scoped(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        user = SimpleUser(id='1')
        authorize.set_access_cookies(
            authorize.create_access_token(user_claims=user),
            key=ACCESS_KEY,
            path=TENANT_PATH,
            csrf_key=ACCESS_CSRF_KEY,
            csrf_path=TENANT_PATH,
        )
        authorize.set_refresh_cookies(
            authorize.create_refresh_token(user_claims=user),
            key=REFRESH_KEY,
            path=f'{TENANT_PATH}/auth',
            csrf_key=REFRESH_CSRF_KEY,
            csrf_path=TENANT_PATH,
        )
        return {'msg': 'ok'}

    @app.get('/logout-scoped')
    def logout_scoped(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        authorize.unset_access_cookies(key=ACCESS_KEY, path=TENANT_PATH, csrf_key=ACCESS_CSRF_KEY, csrf_path=TENANT_PATH)
        authorize.unset_refresh_cookies(key=REFRESH_KEY, path=f'{TENANT_PATH}/auth', csrf_key=REFRESH_CSRF_KEY, csrf_path=TENANT_PATH)
        return {'msg': 'ok'}

    @app.get('/login-samesite')
    def login_samesite(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        authorize.set_access_cookies(authorize.create_access_token(user_claims=SimpleUser(id='1')), samesite='strict')
        return {'msg': 'ok'}

    @app.get('/login-cross-site')
    def login_cross_site(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        authorize.set_access_cookies(authorize.create_access_token(user_claims=SimpleUser(id='1')), samesite='none')
        return {'msg': 'ok'}

    @app.get('/login-domain')
    def login_domain(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        user = SimpleUser(id='1')
        authorize.set_access_cookies(
            authorize.create_access_token(user_claims=user),
            key=ACCESS_KEY,
            path=TENANT_PATH,
            domain=TENANT_DOMAIN,
            csrf_key=ACCESS_CSRF_KEY,
            csrf_path=TENANT_PATH,
        )
        authorize.set_refresh_cookies(
            authorize.create_refresh_token(user_claims=user),
            key=REFRESH_KEY,
            path=f'{TENANT_PATH}/auth',
            domain=TENANT_DOMAIN,
            csrf_key=REFRESH_CSRF_KEY,
            csrf_path=TENANT_PATH,
        )
        return {'msg': 'ok'}

    @app.get('/logout-domain')
    def logout_domain(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        authorize.unset_jwt_cookies(
            access_key=ACCESS_KEY,
            access_path=TENANT_PATH,
            access_domain=TENANT_DOMAIN,
            access_csrf_key=ACCESS_CSRF_KEY,
            access_csrf_path=TENANT_PATH,
            refresh_key=REFRESH_KEY,
            refresh_path=f'{TENANT_PATH}/auth',
            refresh_domain=TENANT_DOMAIN,
            refresh_csrf_key=REFRESH_CSRF_KEY,
            refresh_csrf_path=TENANT_PATH,
        )
        return {'msg': 'ok'}

    @app.get('/logout-scoped-together')
    def logout_scoped_together(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        authorize.unset_jwt_cookies(
            access_key=ACCESS_KEY,
            access_path=TENANT_PATH,
            access_csrf_key=ACCESS_CSRF_KEY,
            access_csrf_path=TENANT_PATH,
            refresh_key=REFRESH_KEY,
            refresh_path=f'{TENANT_PATH}/auth',
            refresh_csrf_key=REFRESH_CSRF_KEY,
            refresh_csrf_path=TENANT_PATH,
        )
        return {'msg': 'ok'}

    @app.get('/logout-half-scoped')
    def logout_half_scoped(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        authorize.unset_jwt_cookies(access_key=ACCESS_KEY, access_path=TENANT_PATH, access_csrf_key=ACCESS_CSRF_KEY, access_csrf_path=TENANT_PATH)
        return {'msg': 'ok'}

    @app.get('/login-default')
    def login_default(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        user = SimpleUser(id='1')
        authorize.set_access_cookies(authorize.create_access_token(user_claims=user))
        authorize.set_refresh_cookies(authorize.create_refresh_token(user_claims=user))
        return {'msg': 'ok'}

    @app.get('/logout-default')
    def logout_default(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        authorize.unset_jwt_cookies()
        return {'msg': 'ok'}

    yield TestClient(app)

    JWTHarmonyBase._config = None
    JWTHarmonyBase._user_model_class = None
    JWTHarmonyBase._token_in_denylist_callback = None


def attributes_of(response, cookie_name):
    """Every attribute of the named Set-Cookie header, lower-cased keys, or None when the cookie is absent."""
    for header in response.headers.get_list('set-cookie'):
        if not header.startswith(f'{cookie_name}='):
            continue
        attributes = {}
        for part in header.split(';')[1:]:
            key, _, value = part.strip().partition('=')
            attributes[key.lower()] = value
        return attributes
    return None


def names_of(response):
    """The names of every cookie the response sets."""
    return [header.split('=', 1)[0] for header in response.headers.get_list('set-cookie')]


def test_the_access_cookies_take_the_name_and_path_the_call_gives(client):
    response = client.get('/login-scoped')

    assert attributes_of(response, ACCESS_KEY)['path'] == TENANT_PATH
    assert attributes_of(response, ACCESS_CSRF_KEY)['path'] == TENANT_PATH


def test_the_refresh_cookies_take_the_name_and_path_the_call_gives(client):
    response = client.get('/login-scoped')

    assert attributes_of(response, REFRESH_KEY)['path'] == f'{TENANT_PATH}/auth'
    assert attributes_of(response, REFRESH_CSRF_KEY)['path'] == TENANT_PATH


def test_a_call_that_names_its_cookies_sets_no_configured_one(client):
    response = client.get('/login-scoped')

    assert names_of(response) == [ACCESS_KEY, ACCESS_CSRF_KEY, REFRESH_KEY, REFRESH_CSRF_KEY]


def test_the_cookies_are_cleared_where_they_were_set(client):
    response = client.get('/logout-scoped')

    assert names_of(response) == [ACCESS_KEY, ACCESS_CSRF_KEY, REFRESH_KEY, REFRESH_CSRF_KEY]
    assert attributes_of(response, ACCESS_KEY)['path'] == TENANT_PATH
    assert attributes_of(response, ACCESS_CSRF_KEY)['path'] == TENANT_PATH
    assert attributes_of(response, REFRESH_KEY)['path'] == f'{TENANT_PATH}/auth'
    assert attributes_of(response, REFRESH_CSRF_KEY)['path'] == TENANT_PATH
    assert attributes_of(response, ACCESS_KEY)['max-age'] == '0'


def test_one_call_clears_every_cookie_the_scoped_login_set(client):
    response = client.get('/logout-scoped-together')

    assert names_of(response) == [ACCESS_KEY, ACCESS_CSRF_KEY, REFRESH_KEY, REFRESH_CSRF_KEY]
    assert attributes_of(response, ACCESS_KEY)['path'] == TENANT_PATH
    assert attributes_of(response, ACCESS_CSRF_KEY)['path'] == TENANT_PATH
    assert attributes_of(response, REFRESH_KEY)['path'] == f'{TENANT_PATH}/auth'
    assert attributes_of(response, REFRESH_CSRF_KEY)['path'] == TENANT_PATH
    assert attributes_of(response, REFRESH_KEY)['max-age'] == '0'


def test_naming_the_access_half_leaves_the_refresh_half_configured(client):
    response = client.get('/logout-half-scoped')

    assert names_of(response) == [ACCESS_KEY, ACCESS_CSRF_KEY, 'refresh_token_cookie', 'csrf_refresh_token']
    assert attributes_of(response, ACCESS_KEY)['path'] == TENANT_PATH
    assert attributes_of(response, 'refresh_token_cookie')['path'] == '/'


def test_the_samesite_the_call_gives_reaches_the_token_and_its_csrf_cookie(client):
    response = client.get('/login-samesite')

    assert attributes_of(response, 'access_token_cookie')['samesite'] == 'strict'
    assert attributes_of(response, 'csrf_access_token')['samesite'] == 'strict'


def test_samesite_none_is_refused_while_the_cookies_are_not_secure(client):
    with pytest.raises(ValueError, match='cookie_secure'):
        client.get('/login-cross-site')


def test_a_call_that_names_no_samesite_keeps_the_configured_one(client):
    response = client.get('/login-default')

    assert 'samesite' not in attributes_of(response, 'access_token_cookie')
    assert 'samesite' not in attributes_of(response, 'csrf_access_token')
    assert 'samesite' not in attributes_of(response, 'refresh_token_cookie')
    assert 'samesite' not in attributes_of(response, 'csrf_refresh_token')


def test_the_domain_the_call_gives_reaches_the_token_and_its_csrf_cookie(client):
    response = client.get('/login-domain')

    assert attributes_of(response, ACCESS_KEY)['domain'] == TENANT_DOMAIN
    assert attributes_of(response, ACCESS_CSRF_KEY)['domain'] == TENANT_DOMAIN
    assert attributes_of(response, REFRESH_KEY)['domain'] == TENANT_DOMAIN
    assert attributes_of(response, REFRESH_CSRF_KEY)['domain'] == TENANT_DOMAIN


def test_the_cookies_are_cleared_on_the_domain_they_were_set_on(client):
    response = client.get('/logout-domain')

    assert attributes_of(response, ACCESS_KEY)['domain'] == TENANT_DOMAIN
    assert attributes_of(response, ACCESS_CSRF_KEY)['domain'] == TENANT_DOMAIN
    assert attributes_of(response, REFRESH_KEY)['domain'] == TENANT_DOMAIN
    assert attributes_of(response, REFRESH_CSRF_KEY)['domain'] == TENANT_DOMAIN
    assert attributes_of(response, ACCESS_KEY)['max-age'] == '0'


def test_a_call_that_names_no_domain_sets_none(client):
    response = client.get('/login-default')

    assert 'domain' not in attributes_of(response, 'access_token_cookie')
    assert 'domain' not in attributes_of(response, 'csrf_access_token')
    assert 'domain' not in attributes_of(response, 'refresh_token_cookie')
    assert 'domain' not in attributes_of(response, 'csrf_refresh_token')


def test_a_call_that_names_nothing_keeps_the_configured_cookies(client):
    response = client.get('/login-default')

    assert names_of(response) == ['access_token_cookie', 'csrf_access_token', 'refresh_token_cookie', 'csrf_refresh_token']
    assert attributes_of(response, 'access_token_cookie')['path'] == '/'
    assert attributes_of(response, 'refresh_token_cookie')['path'] == '/'


def test_the_configured_cookies_are_still_cleared_by_name(client):
    response = client.get('/logout-default')

    assert names_of(response) == ['access_token_cookie', 'csrf_access_token', 'refresh_token_cookie', 'csrf_refresh_token']
    assert attributes_of(response, 'access_token_cookie')['max-age'] == '0'
