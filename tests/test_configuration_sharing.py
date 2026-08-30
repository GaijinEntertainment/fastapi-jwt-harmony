"""Configuration is one thing, shared by every entry point, and `configure` is authoritative."""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyBare, JWTHarmonyWS
from fastapi_jwt_harmony.base import JWTHarmonyBase
from fastapi_jwt_harmony.config import JWTHarmonyConfig
from tests.user_models import SimpleUser


@pytest.fixture(autouse=True)
def _clean_configuration():
    yield
    JWTHarmonyBase._config = None
    JWTHarmonyBase._user_model_class = None
    JWTHarmonyBase._token_in_denylist_callback = None


def test_configuring_the_http_class_also_configures_the_websocket_one():
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(secret_key='testing'))

    assert JWTHarmonyWS[SimpleUser]().config.secret_key == 'testing'


def test_an_omitted_config_yields_usable_defaults_rather_than_an_unconfigured_package():
    JWTHarmony.configure(SimpleUser)

    assert JWTHarmony[SimpleUser]().config.algorithm == 'HS256'


def test_a_denylist_callback_can_be_withdrawn():
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(secret_key='testing'), denylist_callback=lambda _payload: True)
    assert JWTHarmonyBase._token_in_denylist_callback is not None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(secret_key='testing'))

    assert JWTHarmonyBase._token_in_denylist_callback is None


# The old reset idiom wrote onto the subclass, which shadowed the base through the MRO and
# survived configuring. It has to lose to an explicit `configure`.
def test_configuring_overrides_a_value_assigned_onto_a_subclass():
    JWTHarmony._config = None

    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(secret_key='testing'))

    assert JWTHarmony[SimpleUser]().config.secret_key == 'testing'


def test_both_entry_points_see_the_same_configuration_object():
    JWTHarmony.configure(SimpleUser, JWTHarmonyConfig(secret_key='testing', access_token_expires=123))

    app = FastAPI()

    @app.get('/expiry')
    def expiry(authorize: JWTHarmony[SimpleUser] = Depends(JWTHarmonyBare)):
        return {'http': authorize.config.access_token_expires, 'ws': JWTHarmonyWS[SimpleUser]().config.access_token_expires}

    body = TestClient(app).get('/expiry').json()

    assert body == {'http': 123, 'ws': 123}
