"""FastAPI JWT authentication dependencies."""

from typing import Callable, Literal

from fastapi import Query, Request, Response

from .base import UserModelT
from .fastapi_auth import JWTHarmony
from .websocket_auth import JWTHarmonyWS

__all__ = [
    'JWTHarmony',
    'JWTHarmonyWS',
    'JWTHarmonyDep',
    'JWTHarmonyOptional',
    'JWTHarmonyRefresh',
    'JWTHarmonyFresh',
    'JWTHarmonyBare',
    'JWTHarmonyWebSocket',
    'JWTHarmonyWebSocketDep',
    'JWTHarmonyWebSocketOptional',
    'JWTHarmonyWebSocketRefresh',
    'JWTHarmonyWebSocketFresh',
]


def _create_http_dependency(method: Literal['required', 'optional', 'refresh', 'fresh', 'bare']) -> Callable[[Request, Response], JWTHarmony[UserModelT]]:
    """Create HTTP dependency with specified JWT validation method."""

    def dependency(request: Request, response: Response) -> JWTHarmony[UserModelT]:
        instance: JWTHarmony[UserModelT] = JWTHarmony(req=request, res=response)

        if method == 'required':
            instance.jwt_required()
        elif method == 'optional':
            instance.jwt_optional()
        elif method == 'refresh':
            instance.jwt_refresh_token_required()
        elif method == 'fresh':
            instance.fresh_jwt_required()
        # 'bare' doesn't need any validation

        return instance

    return dependency


# The WebSocket dependencies read the token from a query parameter, because the browser WebSocket
# API cannot send an Authorization header. A URL is recorded in far more places than a header is —
# server and proxy access logs, browser history, Referer — so prefer a cookie where the connection
# is same-origin, and treat a token sent this way as short-lived.
def _create_websocket_dependency(
    method: Literal['bare', 'required', 'optional', 'refresh', 'fresh'], token_required: bool = False
) -> Callable[..., JWTHarmonyWS[UserModelT]]:
    """Create WebSocket dependency with specified JWT validation method."""
    if method == 'bare':

        def bare_dependency() -> JWTHarmonyWS[UserModelT]:
            return JWTHarmonyWS()

        return bare_dependency

    def token_dependency(token: str = Query(...) if token_required else Query('')) -> JWTHarmonyWS[UserModelT]:
        instance: JWTHarmonyWS[UserModelT] = JWTHarmonyWS()

        if method == 'required':
            instance.jwt_required(token)
        elif method == 'optional':
            instance.jwt_optional(token)
        elif method == 'refresh':
            instance.jwt_refresh_token_required(token)
        elif method == 'fresh':
            instance.fresh_jwt_required(token)

        return instance

    return token_dependency


# HTTP dependencies
JWTHarmonyDep = _create_http_dependency('required')
JWTHarmonyOptional = _create_http_dependency('optional')
JWTHarmonyRefresh = _create_http_dependency('refresh')
JWTHarmonyFresh = _create_http_dependency('fresh')
JWTHarmonyBare = _create_http_dependency('bare')

# WebSocket dependencies
JWTHarmonyWebSocket = _create_websocket_dependency('bare')
JWTHarmonyWebSocketDep = _create_websocket_dependency('required', token_required=True)
JWTHarmonyWebSocketOptional = _create_websocket_dependency('optional', token_required=False)
JWTHarmonyWebSocketRefresh = _create_websocket_dependency('refresh', token_required=True)
JWTHarmonyWebSocketFresh = _create_websocket_dependency('fresh', token_required=True)
