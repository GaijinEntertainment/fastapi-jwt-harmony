# API Reference

Complete API documentation for FastAPI JWT Harmony.

## Table of Contents

- [Configuration](#configuration)
- [Main Classes](#main-classes)
- [Dependencies](#dependencies)
- [Exceptions](#exceptions)
- [Utilities](#utilities)

## Configuration

### JWTHarmonyConfig

The main configuration class using Pydantic for validation.

```python
class JWTHarmonyConfig(BaseSettings):
    # Core settings
    secret_key: str | None = None
    public_key: str | None = None
    private_key: str | None = None
    algorithm: str = "HS256"
    decode_algorithms: list[str] | None = None
    decode_leeway: int = 0
    encode_issuer: str | None = None
    decode_issuer: str | None = None
    decode_audience: str | list[str] | None = None

    # Token location and validation
    token_location: frozenset[Literal["headers", "cookies"]] = frozenset({"cookies"})
    denylist_enabled: bool = False
    denylist_token_checks: set[str] = {"access", "refresh"}

    # Headers configuration
    header_name: str = "Authorization"
    header_type: str = "Bearer"

    # Token expiration
    access_token_expires: bool | int | timedelta = 900  # 15 minutes
    refresh_token_expires: bool | int | timedelta = 2592000  # 30 days

    # Cookies configuration
    access_cookie_key: str = "access_token_cookie"
    refresh_cookie_key: str = "refresh_token_cookie"
    access_cookie_path: str = "/"
    refresh_cookie_path: str = "/"
    cookie_domain: str | None = None
    cookie_secure: bool = False
    cookie_samesite: str | None = None

    # CSRF protection
    cookie_csrf_protect: bool = True
    access_csrf_cookie_key: str = "csrf_access_token"
    refresh_csrf_cookie_key: str = "csrf_refresh_token"
    access_csrf_cookie_path: str = "/"
    refresh_csrf_cookie_path: str = "/"
    access_csrf_header_name: str = "X-CSRF-Token"
    refresh_csrf_header_name: str = "X-CSRF-Token"
    csrf_methods: set[str] = {"POST", "PUT", "DELETE", "PATCH"}
```

## Main Classes

### JWTHarmony[UserModelT]

The main HTTP authentication class for FastAPI applications.

#### Initialization

```python
def __init__(self, req: Optional[Request] = None, res: Optional[Response] = None) -> None
```

#### Class Methods

```python
@classmethod
def configure(
    cls,
    user_model_class: type[UserModelT],
    config: Optional[Union[JWTHarmonyConfig, dict[str, Any]]] = None,
    denylist_callback: Optional[Callable[[dict[str, Union[str, int, bool]]], bool]] = None
) -> None
```

Configure the JWT authentication system with either a JWTHarmonyConfig object or a dictionary.

#### Token Creation

```python
def create_access_token(
    self,
    subject: Optional[Union[str, int]] = None,
    fresh: Optional[bool] = False,
    algorithm: Optional[str] = None,
    headers: Optional[dict[str, Any]] = None,
    expires_time: Optional[Union[timedelta, int, bool]] = None,
    audience: Optional[Union[str, list[str]]] = None,
    user_claims: Optional[Union[dict[str, Any], UserModelT]] = None,
) -> str
```

Create a new access token.

```python
def create_refresh_token(
    self,
    subject: Optional[Union[str, int]] = None,
    algorithm: Optional[str] = None,
    headers: Optional[dict[str, Any]] = None,
    expires_time: Optional[Union[timedelta, int, bool]] = None,
    audience: Optional[Union[str, list[str]]] = None,
    user_claims: Optional[Union[dict[str, Any], UserModelT]] = None,
) -> str
```

Create a new refresh token.

#### Token Validation

```python
def jwt_required(self) -> None
```

Verify JWT token is present and valid.

```python
def jwt_optional(self) -> None
```

Optionally verify JWT token if present.

```python
def jwt_refresh_token_required(self) -> None
```

Verify refresh token is present and valid.

```python
def fresh_jwt_required(self) -> None
```

Verify fresh access token is present and valid.

#### Cookie Management

```python
def set_access_cookies(
    self,
    encoded_access_token: str,
    response: Optional[Response] = None,
    max_age: Optional[int] = None,
    *,
    key: Optional[str] = None,
    path: Optional[str] = None,
    domain: Optional[str] = None,
    samesite: Optional[Literal['strict', 'lax', 'none']] = None,
    csrf_key: Optional[str] = None,
    csrf_path: Optional[str] = None
) -> None
```

Set access token cookie. `key`, `path`, `domain`, `csrf_key` and `csrf_path`
address the cookies for this call; each falls back to its configured value.
`domain` and `samesite` cover the token cookie and its CSRF cookie together, the
two belonging to one site.

`samesite` shapes a cookie rather than addressing it, so it is offered on the
setters only: a browser identifies a cookie by name, domain and path, and clears
it whatever SameSite the deletion carries. `samesite='none'` raises `ValueError`
unless `cookie_secure` is set, the rule browsers enforce.

`cookie_secure` has no per-call form. It is the one attribute whose per-call
value could only weaken a cookie, and no request-scoped reason to weaken one
exists.

```python
def set_refresh_cookies(
    self,
    encoded_refresh_token: str,
    response: Optional[Response] = None,
    max_age: Optional[int] = None,
    *,
    key: Optional[str] = None,
    path: Optional[str] = None,
    domain: Optional[str] = None,
    samesite: Optional[Literal['strict', 'lax', 'none']] = None,
    csrf_key: Optional[str] = None,
    csrf_path: Optional[str] = None
) -> None
```

Set refresh token cookie, with the same per-call addressing.

```python
def unset_jwt_cookies(
    self,
    response: Optional[Response] = None,
    *,
    access_key: Optional[str] = None,
    access_path: Optional[str] = None,
    access_domain: Optional[str] = None,
    access_csrf_key: Optional[str] = None,
    access_csrf_path: Optional[str] = None,
    refresh_key: Optional[str] = None,
    refresh_path: Optional[str] = None,
    refresh_domain: Optional[str] = None,
    refresh_csrf_key: Optional[str] = None,
    refresh_csrf_path: Optional[str] = None
) -> None
```

Remove all four JWT cookies in one call. The access and refresh halves are named
separately, because a scoped application gives them paths of their own; each
argument falls back to its configured value, so a half that names nothing clears
the configured cookies of that half.

```python
def unset_access_cookies(
    self,
    response: Optional[Response] = None,
    *,
    key: Optional[str] = None,
    path: Optional[str] = None,
    domain: Optional[str] = None,
    csrf_key: Optional[str] = None,
    csrf_path: Optional[str] = None
) -> None
```

Remove access token cookies. A cookie is cleared only where it was set, so a
call that addressed one addresses it again here — domain included.

```python
def unset_refresh_cookies(
    self,
    response: Optional[Response] = None,
    *,
    key: Optional[str] = None,
    path: Optional[str] = None,
    domain: Optional[str] = None,
    csrf_key: Optional[str] = None,
    csrf_path: Optional[str] = None
) -> None
```

Remove refresh token cookies, with the same per-call addressing.

#### Token Information

```python
def get_jwt_subject(self) -> Optional[str]
```

Get the subject (sub claim) from the current JWT token.

```python
def get_jti(self) -> Optional[str]
```

Get the JWT ID (jti claim) from the current token.

```python
def get_raw_jwt(self, encoded_token: Optional[str] = None) -> Optional[dict[str, Union[str, int, bool]]]
```

Get raw JWT payload.

```python
def get_unverified_jwt_headers(self, encoded_token: Optional[str] = None) -> Optional[dict[str, Any]]
```

Get JWT headers without verification.

#### Properties

```python
@property
def token(self) -> Optional[str]
```

Current JWT token.

```python
@property
def user_claims(self) -> Optional[UserModelT]
```

User claims as typed Pydantic model.

```python
@property
def config(self) -> JWTHarmonyConfig
```

Current configuration.

### JWTHarmonyWS[UserModelT]

WebSocket-specific JWT authentication class.

#### Initialization

```python
def __init__(self) -> None
```

#### WebSocket-Specific Methods

```python
def set_websocket(self, websocket: WebSocket) -> None
```

Set WebSocket connection for cookie-based auth.

```python
def set_csrf_token(self, csrf_token: str) -> None
```

Set CSRF token for cookie-based WebSocket auth.

```python
def jwt_required(self, token: Optional[str] = None) -> None
```

Verify JWT token for WebSocket connection.

```python
def jwt_optional(self, token: Optional[str] = None) -> None
```

Optionally verify JWT token for WebSocket.

```python
def jwt_refresh_token_required(self, token: Optional[str] = None) -> None
```

Verify refresh token for WebSocket.

```python
def fresh_jwt_required(self, token: Optional[str] = None) -> None
```

Verify fresh token for WebSocket.

## Dependencies

### JWTHarmonyDep

Dependency that requires a valid access token.

```python
def JWTHarmonyDep(
    req: Request = None,
    res: Response = None
) -> JWTHarmony[Any]
```

### JWTHarmonyOptional

Dependency that optionally validates JWT tokens.

```python
def JWTHarmonyOptional(
    req: Request = None,
    res: Response = None
) -> JWTHarmony[Any]
```

### JWTHarmonyRefresh

Dependency that requires a valid refresh token.

```python
def JWTHarmonyRefresh(
    req: Request = None,
    res: Response = None
) -> JWTHarmony[Any]
```

### JWTHarmonyFresh

Dependency that requires a fresh access token.

```python
def JWTHarmonyFresh(
    req: Request = None,
    res: Response = None
) -> JWTHarmony[Any]
```

### JWTHarmonyBare

Dependency with no automatic token validation.

```python
def JWTHarmonyBare(
    req: Request = None,
    res: Response = None
) -> JWTHarmony[Any]
```

### JWTHarmonyWebSocket

WebSocket dependency for JWT authentication.

```python
def JWTHarmonyWebSocket() -> JWTHarmonyWS[Any]
```

## Exceptions

### JWTHarmonyException

Base exception class for all JWT Harmony errors.

```python
class JWTHarmonyException(Exception):
    def __init__(self, status_code: int, message: str)
```

### Specific Exceptions

- **MissingTokenError**: Token is missing from request
- **JWTDecodeError**: Token is invalid or malformed
- **InvalidHeaderError**: Authorization header is malformed
- **TokenExpired**: Token has expired
- **FreshTokenRequired**: Fresh token is required
- **AccessTokenRequired**: Access token is required
- **RefreshTokenRequired**: Refresh token is required
- **RevokedTokenError**: Token has been revoked
- **CSRFError**: CSRF token is missing or invalid

All exceptions inherit from `JWTHarmonyException` and include:
- `status_code`: HTTP status code
- `message`: Error description

## Utilities

### get_jwt_identifier()

```python
def get_jwt_identifier() -> str
```

Generate a unique JWT identifier (jti).

## Type Definitions

### UserModelT

Type variable representing a Pydantic BaseModel for user data.

```python
UserModelT = TypeVar('UserModelT', bound=BaseModel)
```

### TokenLocation

Literal type for token location options.

```python
TokenLocation = Literal["headers", "cookies"]
```

## Example Usage

### Basic Setup

```python
from fastapi import FastAPI, Depends
from pydantic import BaseModel
from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyDep

app = FastAPI()

class User(BaseModel):
    id: str
    username: str

# Simple configuration with dictionary
JWTHarmony.configure(User, {"secret_key": "secret"})  # pragma: allowlist secret

# Or with JWTHarmonyConfig object for advanced usage
# from fastapi_jwt_harmony import JWTHarmonyConfig
# JWTHarmony.configure(User, JWTHarmonyConfig(secret_key="secret"))  # pragma: allowlist secret

@app.get("/protected")
def protected(auth: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    return {"user": auth.user_claims}
```

### Advanced Configuration

```python
from datetime import timedelta

# With dictionary (simple)
config_dict = {
    "secret_key": "your-secret-key",  # pragma: allowlist secret
    "token_location": {"headers", "cookies"},
    "access_token_expires": timedelta(minutes=15),
    "refresh_token_expires": timedelta(days=30),
    "cookie_csrf_protect": True,
    "cookie_secure": True,
    "cookie_samesite": "strict",
}

JWTHarmony.configure(User, config_dict)

# Or with JWTHarmonyConfig object (advanced)
# from fastapi_jwt_harmony import JWTHarmonyConfig
# config = JWTHarmonyConfig(
#     secret_key="your-secret-key",  # pragma: allowlist secret
#     token_location={"headers", "cookies"},
#     access_token_expires=timedelta(minutes=15),
#     refresh_token_expires=timedelta(days=30),
#     cookie_csrf_protect=True,
#     cookie_secure=True,
#     cookie_samesite="strict",
# )
# JWTHarmony.configure(User, config)
```

### With Denylist

```python
denylist = set()

def check_if_token_revoked(jwt_payload: dict) -> bool:
    return jwt_payload["jti"] in denylist

JWTHarmony.configure(
    User,
    {
        "secret_key": "secret",  # pragma: allowlist secret
        "denylist_enabled": True,
    },
    denylist_callback=check_if_token_revoked
)
```
