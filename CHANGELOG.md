# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `JWTHarmonyConfig` declared every field default positionally
  (`Field(None, ...)`). Pydantic v2 deprecated that form and pyright does not
  read it as a default at all, so a project type-checking in strict mode saw
  all 29 of them as required and could not construct the config. The defaults
  are now passed as `default=`, with no change in behaviour.

## [0.2.2] - 2026-07-03

### Security
- Reject a token whose header `alg` is not in the configured allow-list before
  selecting a decode key, so a crafted `alg` header can no longer trigger an
  unhandled `RuntimeError` (HTTP 500). An accepted-but-unprovisioned algorithm
  (e.g. a legacy symmetric alg listed in `decode_algorithms` with no
  `secret_key`) now also rejects cleanly with `422` instead of `500`.
- Run the denylist callback against the *verified* token payload instead of the
  unverified one, so attacker-controlled claims can no longer drive denylist
  lookups before signature verification.

### Fixed
- `user_claims` no longer returns `None` when `audience`/`issuer` are configured:
  `aud`/`iss` are now treated as reserved claims consistently on both the encode
  and decode sides.
- Accept a falsy-but-present `subject` (e.g. `0` or `""`) when creating a token
  instead of rejecting it as missing.
- In headers+cookies mode, an invalid or malformed header token now falls back to
  cookie authentication instead of failing the request outright; the specific
  header error (e.g. `TokenExpired` with its `jti`) is still surfaced when no
  cookie is available to try.
- `unset_access_cookies`/`unset_refresh_cookies` now emit the `secure` and
  `samesite` attributes so browsers reliably clear the cookies.

### Changed
- The verified token payload is cached per request, so a token is verified and
  denylist-checked at most once per request.
- `JWTHarmonyConfig` now rejects `cookie_samesite='none'` unless `cookie_secure`
  is `True`, matching the browser requirement for `SameSite=None` cookies.

### Added
- Initial release of FastAPI JWT Harmony
- Type-safe JWT authentication with Pydantic integration
- FastAPI dependency injection system with multiple dependency types
- Support for both header and cookie-based authentication
- CSRF protection for cookie authentication
- WebSocket authentication support
- Token denylist/blacklist functionality
- Asymmetric algorithm support (RS256, ES256, etc.)
- Comprehensive test suite with 111+ passing tests
- Modern src-layout project structure

### Features
- **JWTHarmony** - Main HTTP authentication class
- **JWTHarmonyWS** - WebSocket authentication class
- **JWTHarmonyConfig** - Pydantic-based configuration
- **Multiple Dependencies**:
  - `JWTHarmonyDep` - Requires valid access token
  - `JWTHarmonyOptional` - Optional JWT validation
  - `JWTHarmonyRefresh` - Requires valid refresh token
  - `JWTHarmonyFresh` - Requires fresh access token
  - `JWTHarmonyBare` - No automatic validation

### Configuration
- Flexible token location support (headers, cookies, or both)
- Customizable token expiration times
- CSRF protection configuration
- Cookie security settings
- Asymmetric key support
- Token validation options

### Security
- CSRF double-submit cookie pattern
- Secure cookie attributes (HttpOnly, Secure, SameSite)
- Token revocation via denylist
- Clock skew tolerance
- Audience and issuer validation

### Developer Experience
- 100% type coverage with mypy
- Comprehensive documentation
- Modern Python 3.11+ support
- ruff and pylint code quality checks
- Extensive test coverage
- Clear error messages and exception handling

## [0.0.0] - 2024-01-XX

### Added
- Project initialization
- Core authentication framework
- Basic JWT token handling
- FastAPI integration
- Pydantic model support

---

## Migration Guide

### From fastapi-jwt-auth

If you're migrating from `fastapi-jwt-auth`, here are the key changes:

#### Class Names
```python
# Old
from fastapi_jwt_auth import AuthJWT

# New
from fastapi_jwt_harmony import JWTHarmony
```

#### Configuration
```python
# Old
@AuthJWT.load_config
def get_config():
    return Settings()

# New
JWTHarmony.configure(User, JWTHarmonyConfig(...))
```

#### Dependencies
```python
# Old
@app.get("/protected")
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    return {"user": Authorize.get_jwt_subject()}

# New
@app.get("/protected")
def protected(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    return {"user": Authorize.user_claims}  # Typed User model!
```

#### WebSocket Authentication
```python
# Old
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, Authorize: AuthJWT = Depends()):
    Authorize._websocket = websocket  # Hacky
    Authorize.jwt_required()

# New
@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
    Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)
):
    Authorize.jwt_required(token)  # Clean API
```

### Breaking Changes
- Configuration is now done via `JWTHarmony.configure()` instead of decorators
- WebSocket authentication has a dedicated class `JWTHarmonyWS`
- User claims are now typed Pydantic models instead of raw dictionaries
- Dependency injection is more explicit with typed dependencies
- Project structure moved to src-layout

### Benefits of Migration
- **Type Safety**: Full mypy support with typed user claims
- **Better API**: Cleaner, more explicit dependency injection
- **Enhanced Security**: Improved CSRF protection and cookie handling
- **Modern Codebase**: Python 3.11+, latest best practices
- **Better Documentation**: Comprehensive examples and guides
