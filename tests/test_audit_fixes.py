"""Regression tests for the issues reported in docs/audit/."""

import os

import jwt
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from jwt.algorithms import has_crypto
from pydantic import BaseModel, ConfigDict, ValidationError

from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyBare, JWTHarmonyDep
from fastapi_jwt_harmony.config import JWTHarmonyConfig
from fastapi_jwt_harmony.exceptions import JWTDecodeError, JWTHarmonyException
from tests.user_models import SimpleUser


@pytest.mark.skipif(not has_crypto, reason='cryptography not installed')
def test_crafted_alg_header_does_not_500(tmp_path):
    """Audit #1: a crafted `alg` header must yield a clean 422, never an unhandled 500.

    When the server is configured for an asymmetric algorithm with no symmetric
    secret_key, an attacker-supplied HS256 token used to raise a bare RuntimeError
    (HTTP 500). It must now surface as JWTDecodeError (422).
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    JWTHarmony._config = None
    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(
            token_location='headers',
            algorithm='RS256',
            private_key=private_pem,
            public_key=public_pem,
            secret_key=None,
        ),
    )

    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/protected')
    def protected(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'hello': 'world'}

    client = TestClient(app, raise_server_exceptions=False)
    forged = jwt.encode({'sub': '1', 'type': 'access', 'fresh': False}, 'attacker', algorithm='HS256')
    response = client.get('/protected', headers={'Authorization': f'Bearer {forged}'})

    assert response.status_code == 422
    assert response.json() == {'detail': 'The specified alg value is not allowed'}


def test_user_claims_ignores_aud_and_iss_on_strict_model():
    """Audit #4: aud/iss are reserved claims and must be stripped before rebuilding the user model."""

    class StrictUser(BaseModel):
        model_config = ConfigDict(extra='forbid')
        id: str
        role: str = 'user'

    JWTHarmony._config = None
    JWTHarmony.configure(
        StrictUser,
        JWTHarmonyConfig(
            token_location='headers',
            secret_key='secret-key',
            encode_issuer='urn:app',
            decode_issuer='urn:app',
            decode_audience={'aud1'},
        ),
    )

    auth = JWTHarmony[StrictUser]()
    auth._token = auth.create_access_token(user_claims={'id': '42', 'role': 'admin'}, audience='aud1')

    claims = auth.user_claims
    assert claims is not None
    assert claims.id == '42'
    assert claims.role == 'admin'


@pytest.mark.parametrize('subject', [0, ''])
def test_falsy_subject_is_accepted(subject):
    """Audit #5: a falsy-but-present subject (0, empty string) must not be treated as missing."""
    JWTHarmony._config = None
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(token_location='headers', secret_key='secret-key'))

    auth = JWTHarmony[SimpleUser]()
    auth._token = auth.create_access_token(subject=subject)
    assert auth.get_jwt_subject() == str(subject)


def test_samesite_none_requires_secure():
    """Audit #8: SameSite=None cookies must also be Secure."""
    with pytest.raises(ValidationError, match='cookie_secure'):
        JWTHarmonyConfig(cookie_samesite='none', cookie_secure=False)

    # SameSite=None with Secure=True is accepted.
    config = JWTHarmonyConfig(cookie_samesite='none', cookie_secure=True, secret_key='secret-key')
    assert config.cookie_samesite == 'none'


def test_invalid_header_token_falls_back_to_cookie():
    """Audit #6: in headers+cookies mode, a bad header token must not block a valid cookie token."""
    JWTHarmony._config = None
    JWTHarmony._token_in_denylist_callback = None
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(secret_key='secret', token_location=['headers', 'cookies']))

    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/login')
    def login(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        token = Authorize.create_access_token(user_claims=SimpleUser(id='1'))
        Authorize.set_access_cookies(token)
        return {'ok': True}

    @app.get('/protected')
    def protected(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'sub': Authorize.get_jwt_subject()}

    @app.post('/protected-post')
    def protected_post(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'sub': Authorize.get_jwt_subject()}

    client = TestClient(app)
    client.get('/login')

    # GET (no CSRF required): a garbage header token falls back to the valid cookie.
    response = client.get('/protected', headers={'Authorization': 'Bearer garbage.token.here'})
    assert response.status_code == 200
    assert response.json() == {'sub': '1'}

    # A malformed Authorization header format (wrong scheme / no token) must also
    # fall back to the cookie instead of failing with InvalidHeaderError.
    for bad_header in ['Bearer', 'Basic abc', 'Token xyz']:
        response = client.get('/protected', headers={'Authorization': bad_header})
        assert response.status_code == 200, bad_header
        assert response.json() == {'sub': '1'}

    # POST (CSRF required): the cookie fallback still enforces CSRF - no bypass.
    response = client.post('/protected-post', headers={'Authorization': 'Bearer garbage.token.here'})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Missing CSRF Token'}


def test_malformed_header_still_fails_in_headers_only_mode():
    """The malformed-header fallback must not weaken headers-only auth."""
    JWTHarmony._config = None
    JWTHarmony._token_in_denylist_callback = None
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(secret_key='secret', token_location='headers'))

    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/protected')
    def protected(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'sub': Authorize.get_jwt_subject()}

    client = TestClient(app)
    response = client.get('/protected', headers={'Authorization': 'Basic abc'})
    assert response.status_code == 422
    assert response.json() == {'detail': "Bad Authorization header. Expected value 'Bearer <JWT>'"}


def test_expired_header_token_surfaces_specific_error():
    """Audit #6 follow-up: a bad header token with no cookie must surface its own error.

    The header->cookie fallback must not mask an informative header error (e.g.
    TokenExpired) behind a generic 'Missing cookie' when there is no cookie to try.
    """
    JWTHarmony._config = None
    JWTHarmony._token_in_denylist_callback = None
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(secret_key='secret', token_location=['headers', 'cookies']))

    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/protected')
    def protected(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'sub': Authorize.get_jwt_subject()}

    client = TestClient(app)
    expired = jwt.encode({'sub': '1', 'type': 'access', 'fresh': False, 'exp': 0}, 'secret', algorithm='HS256')
    response = client.get('/protected', headers={'Authorization': f'Bearer {expired}'})
    assert response.status_code == 401
    assert response.json() == {'detail': 'Token expired'}


@pytest.mark.skipif(not has_crypto, reason='cryptography not installed')
def test_crafted_alg_with_multi_algorithm_config_does_not_500():
    """Audit #1 follow-up: a listed-but-unprovisioned algorithm must reject, not 500.

    When decode_algorithms lists a symmetric algorithm but no secret_key is set
    (e.g. after rotating to asymmetric keys), an attacker choosing that algorithm
    must get a clean 422, not an unhandled RuntimeError.
    """
    here = os.path.dirname(__file__)
    with open(os.path.join(here, 'private_key.txt')) as f:
        private_key = f.read().strip()
    with open(os.path.join(here, 'public_key.txt')) as f:
        public_key = f.read().strip()

    JWTHarmony._config = None
    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(
            token_location='headers',
            algorithm='RS256',
            decode_algorithms=['RS256', 'HS256'],
            private_key=private_key,
            public_key=public_key,
            secret_key=None,
        ),
    )

    app = FastAPI()

    @app.exception_handler(JWTHarmonyException)
    def handler(request: Request, exc: JWTHarmonyException):
        return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})

    @app.get('/protected')
    def protected(Authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyDep)):
        return {'ok': True}

    client = TestClient(app, raise_server_exceptions=False)
    forged = jwt.encode({'sub': '1', 'type': 'access', 'fresh': False}, 'attacker', algorithm='HS256')
    response = client.get('/protected', headers={'Authorization': f'Bearer {forged}'})
    assert response.status_code == 422
    assert response.json() == {'detail': 'The specified alg value is not allowed'}


def test_denylist_runs_on_verified_token_only():
    """Audit #3: a token with a bad signature must fail verification, not reach the denylist callback."""
    seen = []

    def callback(decoded):
        seen.append(decoded)
        return False

    JWTHarmony._config = None
    JWTHarmony._token_in_denylist_callback = None
    JWTHarmony.configure(
        SimpleUser,
        JWTHarmonyConfig(token_location='headers', secret_key='right-key', denylist_enabled=True),
        denylist_callback=callback,
    )

    auth = JWTHarmony[SimpleUser]()
    forged = jwt.encode({'sub': '1', 'type': 'access', 'jti': 'x'}, 'wrong-key', algorithm='HS256')
    auth._token = forged

    with pytest.raises(JWTDecodeError):
        auth.get_raw_jwt()
    assert seen == []
