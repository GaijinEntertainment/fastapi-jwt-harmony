import pytest
from fastapi import Depends, FastAPI, Query, WebSocket
from fastapi.testclient import TestClient

from fastapi_jwt_harmony import (
    JWTHarmony,
    JWTHarmonyBare,
    JWTHarmonyWS,
    JWTHarmonyWebSocket,
)
from fastapi_jwt_harmony.config import JWTHarmonyConfig
from fastapi_jwt_harmony.exceptions import JWTHarmonyException
from tests.user_models import SimpleUser

# WebSocket tests require special handling since WebSocket doesn't use Request/Response


@pytest.fixture(scope='function')
def client():
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(secret_key='testing', token_location='headers'))

    # Sync config to websocket class

    app = FastAPI()

    @app.get('/all-token')
    def all_token(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        user = SimpleUser(id='1')
        access_token = Authorize.create_access_token(user_claims=user, fresh=True)
        refresh_token = Authorize.create_refresh_token(user_claims=user)
        Authorize.set_access_cookies(access_token)
        Authorize.set_refresh_cookies(refresh_token)
        return {'msg': 'all token'}

    @app.get('/unset-all-token')
    def unset_all_token(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        Authorize.unset_jwt_cookies()
        return {'msg': 'unset all token'}

    @app.websocket('/jwt-required')
    async def websocket_jwt_required(websocket: WebSocket, token: str = Query(...), Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)):
        await websocket.accept()
        try:
            Authorize.jwt_required(token)
            await websocket.send_text('Successfully Login!')
        except JWTHarmonyException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/jwt-required-cookies')
    async def websocket_jwt_required_cookies(websocket: WebSocket, csrf_token: str = Query(...), Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)):
        await websocket.accept()
        try:
            # For WebSocket with cookies, we need to pass the WebSocket and CSRF token
            Authorize.set_websocket(websocket)
            Authorize.set_csrf_token(csrf_token)
            Authorize.jwt_required()
            await websocket.send_text('Successfully Login!')
        except JWTHarmonyException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/jwt-optional')
    async def websocket_jwt_optional(websocket: WebSocket, token: str = Query(...), Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)):
        await websocket.accept()
        try:
            Authorize.jwt_optional(token)
            decoded_token = Authorize.get_raw_jwt() if Authorize.token else None
            if decoded_token:
                await websocket.send_text('hello world')
            else:
                await websocket.send_text('hello anonym')
        except JWTHarmonyException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/jwt-optional-cookies')
    async def websocket_jwt_optional_cookies(websocket: WebSocket, csrf_token: str = Query(...), Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)):
        await websocket.accept()
        try:
            Authorize.set_websocket(websocket)
            Authorize.set_csrf_token(csrf_token)
            Authorize.jwt_optional()
            decoded_token = Authorize.get_raw_jwt()
            if decoded_token:
                await websocket.send_text('hello world')
            else:
                await websocket.send_text('hello anonym')
        except JWTHarmonyException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/jwt-refresh-required')
    async def websocket_jwt_refresh_required(websocket: WebSocket, token: str = Query(...), Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)):
        await websocket.accept()
        try:
            Authorize.jwt_refresh_token_required(token)
            await websocket.send_text('Successfully Login!')
        except JWTHarmonyException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/jwt-refresh-required-cookies')
    async def websocket_jwt_refresh_required_cookies(
        websocket: WebSocket, csrf_token: str = Query(...), Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)
    ):
        await websocket.accept()
        try:
            Authorize.set_websocket(websocket)
            Authorize.set_csrf_token(csrf_token)
            Authorize.jwt_refresh_token_required()
            await websocket.send_text('Successfully Login!')
        except JWTHarmonyException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/fresh-jwt-required')
    async def websocket_fresh_jwt_required(websocket: WebSocket, token: str = Query(...), Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)):
        await websocket.accept()
        try:
            Authorize.fresh_jwt_required(token)
            await websocket.send_text('Successfully Login!')
        except JWTHarmonyException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    @app.websocket('/fresh-jwt-required-cookies')
    async def websocket_fresh_jwt_required_cookies(websocket: WebSocket, csrf_token: str = Query(...), Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)):
        await websocket.accept()
        try:
            Authorize.set_websocket(websocket)
            Authorize.set_csrf_token(csrf_token)
            Authorize.fresh_jwt_required()
            await websocket.send_text('Successfully Login!')
        except JWTHarmonyException as err:
            await websocket.send_text(err.message)
        await websocket.close()

    client = TestClient(app)
    return client


@pytest.mark.parametrize('url', ['/jwt-required', '/jwt-refresh-required', '/fresh-jwt-required'])
def test_missing_token_websocket(client, url):
    token_type = 'access' if url != '/jwt-refresh-required' else 'refresh'
    with client.websocket_connect(url + '?token=') as websocket:
        data = websocket.receive_text()
        assert data == f'Missing {token_type} token from Query or Path'


@pytest.mark.parametrize('url', ['/jwt-required', '/fresh-jwt-required'])
def test_only_access_token_allowed_websocket(client, url, authorize_fixture):
    user = SimpleUser(id='test')
    token = authorize_fixture.create_refresh_token(user_claims=user)
    with client.websocket_connect(url + f'?token={token}') as websocket:
        data = websocket.receive_text()
        assert data == 'Only access tokens are allowed'


def test_jwt_optional_websocket_accepts_refresh_token(client, authorize_fixture):
    """JWT optional should not fail with refresh token, just treat as anonymous"""
    user = SimpleUser(id='test')
    token = authorize_fixture.create_refresh_token(user_claims=user)
    with client.websocket_connect('/jwt-optional' + f'?token={token}') as websocket:
        data = websocket.receive_text()
        assert data == 'hello anonym'  # Because optional treats invalid tokens as no token


def test_jwt_required_websocket(client, authorize_fixture):
    url = '/jwt-required'
    user = SimpleUser(id='test')
    token = authorize_fixture.create_access_token(user_claims=user)
    with client.websocket_connect(url + f'?token={token}') as websocket:
        data = websocket.receive_text()
        assert data == 'Successfully Login!'


def test_jwt_optional_websocket(client, authorize_fixture):
    url = '/jwt-optional'
    # if token not define return anonym user
    with client.websocket_connect(url + '?token=') as websocket:
        data = websocket.receive_text()
        assert data == 'hello anonym'

    user = SimpleUser(id='test')
    token = authorize_fixture.create_access_token(user_claims=user)
    with client.websocket_connect(url + f'?token={token}') as websocket:
        data = websocket.receive_text()
        assert data == 'hello world'


def test_refresh_required_websocket(client, authorize_fixture):
    url = '/jwt-refresh-required'
    # only refresh token allowed
    user = SimpleUser(id='test')
    token = authorize_fixture.create_access_token(user_claims=user)
    with client.websocket_connect(url + f'?token={token}') as websocket:
        data = websocket.receive_text()
        assert data == 'Only refresh tokens are allowed'

    user = SimpleUser(id='test')
    token = authorize_fixture.create_refresh_token(user_claims=user)
    with client.websocket_connect(url + f'?token={token}') as websocket:
        data = websocket.receive_text()
        assert data == 'Successfully Login!'


def test_fresh_jwt_required_websocket(client, authorize_fixture):
    url = '/fresh-jwt-required'
    # only fresh token allowed
    user = SimpleUser(id='test')
    token = authorize_fixture.create_access_token(user_claims=user)
    with client.websocket_connect(url + f'?token={token}') as websocket:
        data = websocket.receive_text()
        assert data == 'Fresh token required'

    token = authorize_fixture.create_access_token(user_claims=user, fresh=True)
    with client.websocket_connect(url + f'?token={token}') as websocket:
        data = websocket.receive_text()
        assert data == 'Successfully Login!'


# ========= COOKIES ========


def test_invalid_instance_websocket(authorize_fixture):
    # Test that HTTP JWTHarmony instance raises error when used without request
    with pytest.raises(RuntimeError, match=r'Request object is required'):
        authorize_fixture.jwt_required()
    with pytest.raises(RuntimeError, match=r'Request object is required'):
        authorize_fixture.jwt_refresh_token_required()
    with pytest.raises(RuntimeError, match=r'Request object is required'):
        authorize_fixture.fresh_jwt_required()


@pytest.mark.parametrize('url', ['/jwt-required-cookies', '/jwt-refresh-required-cookies', '/fresh-jwt-required-cookies'])
def test_missing_cookie(url, client):
    # Set config to use cookies
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(token_location='cookies', secret_key='testing'))

    cookie_key = 'access_token_cookie' if url != '/jwt-refresh-required-cookies' else 'refresh_token_cookie'
    with client.websocket_connect(url + '?csrf_token=') as websocket:
        data = websocket.receive_text()
        assert data == f'Missing cookie {cookie_key}'


@pytest.mark.parametrize('url', ['/jwt-required-cookies', '/jwt-refresh-required-cookies', '/fresh-jwt-required-cookies', '/jwt-optional-cookies'])
def test_missing_csrf_token(url, client):
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(token_location='cookies', secret_key='secret'))

    # required and optional
    client.get('/all-token')

    with client.websocket_connect(url + '?csrf_token=') as websocket:
        data = websocket.receive_text()
        if url == '/jwt-optional-cookies':
            # For optional endpoints, missing CSRF means no auth (anonym user)
            assert data == 'hello anonym'
        else:
            assert data == 'Missing CSRF Token'

    client.get('/unset-all-token')

    # disable csrf protection
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(token_location='cookies', secret_key='secret', cookie_csrf_protect=False))

    client.get('/all-token')

    msg = 'hello world' if url == '/jwt-optional-cookies' else 'Successfully Login!'
    with client.websocket_connect(url + '?csrf_token=') as websocket:
        data = websocket.receive_text()
        assert data == msg


@pytest.mark.parametrize('url', ['/jwt-required-cookies', '/jwt-refresh-required-cookies', '/fresh-jwt-required-cookies', '/jwt-optional-cookies'])
def test_missing_claim_csrf_in_token(url, client):
    # required and optional
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(token_location='cookies', secret_key='secret', cookie_csrf_protect=False))

    client.get('/all-token')

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(token_location='cookies', secret_key='secret'))

    with client.websocket_connect(url + '?csrf_token=test') as websocket:
        data = websocket.receive_text()
        if url == '/jwt-optional-cookies':
            # For optional endpoints, missing csrf claim means no auth (anonym user)
            assert data == 'hello anonym'
        else:
            assert data == 'Missing claim: csrf'

    # disable csrf protection
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(token_location='cookies', secret_key='secret', cookie_csrf_protect=False))

    msg = 'hello world' if url == '/jwt-optional-cookies' else 'Successfully Login!'
    with client.websocket_connect(url + '?csrf_token=test') as websocket:
        data = websocket.receive_text()
        assert data == msg


@pytest.mark.parametrize('url', ['/jwt-required-cookies', '/jwt-refresh-required-cookies', '/fresh-jwt-required-cookies', '/jwt-optional-cookies'])
def test_invalid_csrf_double_submit(url, client):
    # required and optional
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(token_location='cookies', secret_key='secret'))

    client.get('/all-token')

    with client.websocket_connect(url + '?csrf_token=test') as websocket:
        data = websocket.receive_text()
        if url == '/jwt-optional-cookies':
            # For optional endpoints, CSRF mismatch means no auth (anonym user)
            assert data == 'hello anonym'
        else:
            assert data == 'CSRF double submit tokens do not match'

    # disable csrf protection
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(token_location='cookies', secret_key='secret', cookie_csrf_protect=False))

    msg = 'hello world' if url == '/jwt-optional-cookies' else 'Successfully Login!'
    with client.websocket_connect(url + '?csrf_token=test') as websocket:
        data = websocket.receive_text()
        assert data == msg


@pytest.mark.parametrize('url', ['/jwt-required-cookies', '/jwt-refresh-required-cookies', '/fresh-jwt-required-cookies', '/jwt-optional-cookies'])
def test_valid_access_endpoint_with_csrf(url, client):
    # required and optional
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(token_location='cookies', secret_key='secret'))

    res = client.get('/all-token')
    csrf_access = res.cookies.get('csrf_access_token')
    csrf_refresh = res.cookies.get('csrf_refresh_token')

    if url == '/jwt-refresh-required-cookies':
        with client.websocket_connect(url + f'?csrf_token={csrf_refresh}') as websocket:
            data = websocket.receive_text()
            assert data == 'Successfully Login!'
    else:
        msg = 'hello world' if url == '/jwt-optional-cookies' else 'Successfully Login!'
        with client.websocket_connect(url + f'?csrf_token={csrf_access}') as websocket:
            data = websocket.receive_text()
            assert data == msg
