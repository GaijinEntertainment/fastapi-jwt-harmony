# Documentation Index

Welcome to the FastAPI JWT Harmony documentation! This directory contains comprehensive guides and examples for using the library.

## 📚 Documentation Structure

### Core Documentation
- **[../README.md](../README.md)** - Main project README with quick start guide
- **[API.md](API.md)** - Complete API reference documentation
- **[MIGRATION.md](MIGRATION.md)** - Migration guide from other JWT libraries

### Development
- **[../CONTRIBUTING.md](../CONTRIBUTING.md)** - Contributing guidelines and development setup
- **[../CHANGELOG.md](../CHANGELOG.md)** - Version history and changes

### Examples
All examples are located in the `examples/` directory:

- **[examples/basic_usage.py](examples/basic_usage.py)** - Basic authentication patterns
- **[examples/cookie_auth.py](examples/cookie_auth.py)** - Cookie-based authentication with CSRF
- **[examples/websocket_auth.py](examples/websocket_auth.py)** - WebSocket authentication

## 🚀 Quick Navigation

### Getting Started
1. Read the [main README](../README.md) for installation and basic usage
2. Try the [basic example](examples/basic_usage.py)
3. Check the [API reference](API.md) for detailed documentation

### Common Use Cases
- **Simple JWT auth**: [Basic usage example](examples/basic_usage.py)
- **Secure web apps**: [Cookie auth example](examples/cookie_auth.py)
- **Real-time apps**: [WebSocket example](examples/websocket_auth.py)

### Migration
- **From fastapi-jwt-auth**: See [Migration Guide](MIGRATION.md#from-fastapi-jwt-auth)
- **From python-jose**: See [Migration Guide](MIGRATION.md#from-python-jose)
- **From PyJWT**: See [Migration Guide](MIGRATION.md#from-pyjwt)

## 📖 Learning Path

### Beginner
1. **Installation and Setup**
   - Install: `pip install fastapi-jwt-harmony`
   - Read: [Quick Start](../README.md#quick-start)
   - Try: [Basic Usage Example](examples/basic_usage.py)

2. **Core Concepts**
   - User models with Pydantic
   - JWT configuration
   - Dependency injection patterns

3. **Basic Authentication**
   - Login/logout endpoints
   - Protected routes
   - Token refresh

### Intermediate
1. **Advanced Features**
   - Cookie-based authentication
   - CSRF protection
   - Multiple token locations

2. **WebSocket Support**
   - Real-time authentication
   - Connection management
   - Token validation

3. **Security Best Practices**
   - Token denylist/blacklist
   - Secure cookie settings
   - Asymmetric algorithms

### Advanced
1. **Production Deployment**
   - Environment configuration
   - Performance optimization
   - Monitoring and logging

2. **Custom Extensions**
   - Custom dependencies
   - Middleware integration
   - Advanced validation

3. **Testing and CI/CD**
   - Unit testing patterns
   - Integration testing
   - GitHub Actions setup

## 🔧 API Reference

The complete API is documented in [API.md](API.md), including:

### Main Classes
- **JWTHarmony** - HTTP authentication
- **JWTHarmonyWS** - WebSocket authentication
- **JWTHarmonyConfig** - Configuration

### Dependencies
- **JWTHarmonyDep** - Requires valid access token
- **JWTHarmonyOptional** - Optional authentication
- **JWTHarmonyRefresh** - Requires refresh token
- **JWTHarmonyFresh** - Requires fresh token

### Exceptions
- **JWTHarmonyException** - Base exception
- **TokenExpired** - Token has expired
- **CSRFError** - CSRF validation failed
- And more...

## 💡 Examples Overview

### Basic Usage
Simple authentication with user models:
```python
from fastapi_jwt_harmony import JWTHarmony, JWTHarmonyConfig, JWTHarmonyDep

class User(BaseModel):
    id: str
    username: str

JWTHarmony.configure(User, JWTHarmonyConfig(secret_key="secret"))  # pragma: allowlist secret

@app.get("/protected")
def protected(auth: JWTHarmony[User] = Depends(JWTHarmonyDep)):
    return {"user": auth.user_claims}
```

### Cookie Authentication
Secure cookie-based auth with CSRF protection:
```python
JWTHarmony.configure(
    User,
    JWTHarmonyConfig(
        secret_key="secret",  # pragma: allowlist secret
        token_location={"cookies"},
        cookie_csrf_protect=True
    )
)
```

### WebSocket Authentication
Real-time authentication for WebSocket connections:
```python
from fastapi_jwt_harmony import JWTHarmonyWS, JWTHarmonyWebSocket

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
    auth: JWTHarmonyWS = Depends(JWTHarmonyWebSocket)
):
    auth.jwt_required(token)
    user = auth.user_claims
```

## 🧪 Testing Examples

All examples include comprehensive testing instructions and can be run independently:

```bash
# Run basic example
python docs/examples/basic_usage.py

# Run cookie auth example
python docs/examples/cookie_auth.py

# Run WebSocket example
python docs/examples/websocket_auth.py
```

## 🔗 External Resources

- **FastAPI Documentation**: https://fastapi.tiangolo.com/
- **Pydantic Documentation**: https://docs.pydantic.dev/
- **JWT.io**: https://jwt.io/ - JWT debugger and information
- **OWASP JWT Security**: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

## 📝 Contributing to Documentation

We welcome contributions to improve the documentation! See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

### Documentation Standards
- Clear, concise explanations
- Practical examples for all features
- Code samples that actually work
- Step-by-step instructions
- Cross-references between sections

### Adding Examples
1. Create a new `.py` file in `examples/`
2. Include comprehensive comments
3. Add usage instructions at the bottom
4. Test that the example works
5. Update this index

## 🆘 Getting Help

- **GitHub Issues**: Report bugs or request features
- **Discussions**: Ask questions and share ideas
- **Examples**: Check existing examples for patterns
- **API Docs**: Detailed reference in [API.md](API.md)

Happy coding with FastAPI JWT Harmony! 🎵
