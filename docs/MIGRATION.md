# Migration Guide

This guide helps you migrate from other JWT libraries to FastAPI JWT Harmony.

## Table of Contents

- [From fastapi-jwt-auth](#from-fastapi-jwt-auth)
- [From python-jose](#from-python-jose)
- [From PyJWT](#from-pyjwt)
- [Breaking Changes](#breaking-changes)
- [Benefits](#benefits)

## From fastapi-jwt-auth

FastAPI JWT Harmony is designed as a modern replacement for `fastapi-jwt-auth` with better type safety and API design.

### Package Installation

```bash
# Old
pip install fastapi-jwt-auth

# New
pip install fastapi-jwt-harmony
```

### Import Changes

```python
# Old
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException

# New
from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyDep
from fastapi_jwt_harmony.exceptions import JWTHarmonyException
```

### Configuration

#### Old Way (Decorator Pattern)

```python
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel

class Settings(BaseModel):
    authjwt_secret_key: str = "secret"  # pragma: allowlist secret
    authjwt_denylist_enabled: bool = True

@AuthJWT.load_config
def get_config():
    return Settings()

@AuthJWT.token_in_denylist_loader
def check_if_token_revoked(decrypted_token):
    return decrypted_token['jti'] in denylist
```

#### New Way (Explicit Configuration)

```python
from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyConfig
from pydantic import BaseModel

class User(BaseModel):
    id: str
    username: str

def check_if_token_revoked(decrypted_token):
    return decrypted_token['jti'] in denylist

JWTHarmony.configure(
    User,
    JWTHarmonyConfig(
        secret_key="secret",  # pragma: allowlist secret
        denylist_enabled=True
    ),
    denylist_callback=check_if_token_revoked
)
```

### Dependencies

#### Old Way (Manual Validation)

```python
from fastapi import Depends
from fastapi_jwt_auth import AuthJWT

@app.get("/protected")
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    current_user = Authorize.get_jwt_subject()
    return {"user": current_user}

@app.get("/optional")
def optional(Authorize: AuthJWT = Depends()):
    Authorize.jwt_optional()
    current_user = Authorize.get_jwt_subject()
    return {"user": current_user}
```

#### New Way (Automatic Validation)

```python
from fastapi import Depends
from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyDep, JWTHarmonyOptional

@app.get("/protected")
def protected(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    # JWT automatically validated by JWTHarmonyDep
    current_user = Authorize.user_claims  # Typed User model!
    return {"user": current_user}

@app.get("/optional")
def optional(Authorize: JWTHarmony[User] = Depends(JWTHarmonyOptional)):
    # JWT optionally validated by JWTHarmonyOptional
    current_user = Authorize.user_claims  # May be None
    return {"user": current_user}
```

### WebSocket Authentication

#### Old Way (Hacky)

```python
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, Authorize: AuthJWT = Depends()):
    await websocket.accept()
    Authorize._websocket = websocket  # Accessing private attribute
    try:
        Authorize.jwt_required()
        # ... handle connection
    except AuthJWTException:
        await websocket.close()
```

#### New Way (Clean API)

```python
from fastapi_jwt_harmony import JWTHarmonyWS, JWTHarmonyWebSocket

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
    Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)
):
    await websocket.accept()
    try:
        Authorize.jwt_required(token)  # Clean API
        user = Authorize.user_claims  # Typed user model
        # ... handle connection
    except JWTHarmonyException:
        await websocket.close()
```

### User Claims

#### Old Way (Raw Dictionary)

```python
@app.get("/user")
def get_user(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    claims = Authorize.get_raw_jwt()  # Raw dict
    user_id = claims.get("user_id")   # No type safety
    username = claims.get("username") # Might be missing
    return {"user_id": user_id, "username": username}
```

#### New Way (Typed Pydantic Model)

```python
@app.get("/user")
def get_user(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    user = Authorize.user_claims  # Typed User model
    return {
        "user_id": user.id,        # Type-safe access
        "username": user.username  # IDE completion works
    }
```

## From python-jose

If you're using `python-jose` with FastAPI:

### Old Approach

```python
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer

security = HTTPBearer()

def get_current_user(token: str = Depends(security)):
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        # Manual user lookup from database
        user = get_user_from_db(user_id)
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

### New Approach

```python
from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyConfig, JWTHarmonyDep

JWTHarmony.configure(
    User,
    JWTHarmonyConfig(
        secret_key=SECRET_KEY,  # pragma: allowlist secret
        algorithm=ALGORITHM
    )
)

# User data automatically available from token
def get_current_user(auth: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    return auth.user_claims  # User data embedded in JWT
```

## From PyJWT

If you're using raw PyJWT:

### Old Manual Approach

```python
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer

security = HTTPBearer()

def verify_token(token: str = Depends(security)):
    try:
        payload = jwt.decode(
            token.credentials,
            SECRET_KEY,
            algorithms=["HS256"]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
```

### New Integrated Approach

```python
from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyConfig, JWTHarmonyDep

JWTHarmony.configure(
    User,
    JWTHarmonyConfig(
        secret_key=SECRET_KEY,  # pragma: allowlist secret
        access_token_expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
)

# Automatic token verification
@app.get("/protected")
def protected(auth: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    return {"user": auth.user_claims}

# Simple token creation
@app.post("/login")
def login(auth: JWTHarmony[User] = Depends(JWTHarmonyBare)):
    user = User(id="123", username="john")
    token = auth.create_access_token(user_claims=user)
    return {"access_token": token}
```

## Breaking Changes

### Configuration Method
- **Old**: Decorator-based configuration (`@AuthJWT.load_config`)
- **New**: Explicit method call (`JWTHarmony.configure()`)

### Class Names
- `AuthJWT` → `JWTHarmony`
- `AuthJWTException` → `JWTHarmonyException`
- `AuthJWTConfig` → `JWTHarmonyConfig`

### Dependencies
- **Old**: Manual `jwt_required()` calls in endpoints
- **New**: Automatic validation through dependency types

### WebSocket API
- **Old**: Setting private `_websocket` attribute
- **New**: Dedicated `JWTHarmonyWS` class with clean API

### User Claims
- **Old**: Raw dictionary access
- **New**: Typed Pydantic model properties

### Project Structure
- **Old**: Flat package structure
- **New**: Modern src-layout with `src/fastapi_jwt_harmony/`

## Benefits of Migration

### 🔒 Type Safety
```python
# Old: No type safety
claims = Authorize.get_raw_jwt()
user_id = claims.get("user_id")  # Could be None, no IDE help

# New: Full type safety
user = Authorize.user_claims  # Type: User
user_id = user.id  # Type: str, IDE completion works
```

### 🚀 Better API Design
```python
# Old: Manual validation
@app.get("/protected")
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()  # Easy to forget!
    return get_data()

# New: Automatic validation
@app.get("/protected")
def protected(auth: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    return get_data()  # JWT already validated
```

### 🍪 Enhanced Cookie Support
```python
# Old: Basic cookie support
response.set_cookie("access_token", token)

# New: Secure cookie handling with CSRF protection
auth.set_access_cookies(token, response)  # CSRF tokens included
```

### 🔄 Clean WebSocket API
```python
# Old: Hacky WebSocket auth
Authorize._websocket = websocket  # Accessing private members

# New: Dedicated WebSocket class
Authorize: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)
Authorize.jwt_required(token)  # Clean public API
```

### 📝 Better Documentation
- Comprehensive API documentation
- Type hints for better IDE support
- Extensive examples and guides
- Migration assistance

### 🧪 Robust Testing
- 111+ comprehensive tests
- 100% test coverage
- Multiple Python version support
- Cross-platform testing

## Migration Steps

1. **Install FastAPI JWT Harmony**
   ```bash
   pip install fastapi-jwt-harmony
   ```

2. **Update imports**
   ```python
   # Replace old imports with new ones
   from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyConfig
   ```

3. **Define user model**
   ```python
   from pydantic import BaseModel

   class User(BaseModel):
       id: str
       username: str
       # Add other user fields
   ```

4. **Update configuration**
   ```python
   # Replace decorator with explicit configuration
   JWTHarmony.configure(User, JWTHarmonyConfig(...))
   ```

5. **Update dependencies**
   ```python
   # Replace manual validation with dependency types
   def endpoint(auth: JWTHarmony[User] = Depends(JWTHarmonyDep)):
   ```

6. **Update WebSocket endpoints**
   ```python
   # Use dedicated WebSocket class
   from fastapi_jwt_harmony import JWTHarmonyWS, JWTHarmonyWebSocket
   ```

7. **Test thoroughly**
   ```bash
   # Run your test suite to ensure everything works
   pytest
   ```

## Need Help?

- Check the [API documentation](API.md)
- Browse [examples](examples/)
- Open an issue on GitHub
- Join the community discussions

The migration process is designed to be straightforward while providing significant improvements in type safety, API design, and developer experience.
