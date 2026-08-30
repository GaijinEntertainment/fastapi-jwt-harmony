"""
WebSocket authentication example.

This example demonstrates how to authenticate WebSocket connections
using JWT tokens with both query parameter and cookie-based methods.
"""

import asyncio
from typing import Any, List

from fastapi import Depends, FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from fastapi_jwt_harmony import (
    JWTHarmony,
    JWTHarmonyBare,
    JWTHarmonyConfig,
    JWTHarmonyDep,
    JWTHarmonyException,
    JWTHarmonyWS,
    JWTHarmonyWebSocket,
)

app = FastAPI(title='JWT Harmony WebSocket Example')


# User model
class User(BaseModel):
    id: str
    username: str
    room: str = 'general'


class LoginRequest(BaseModel):
    username: str
    password: str


# Mock user database
USERS_DB = {
    'alice': {'id': '1', 'username': 'alice', 'password': 'secret', 'room': 'general'},  # pragma: allowlist secret
    'bob': {'id': '2', 'username': 'bob', 'password': 'secret', 'room': 'vip'},  # pragma: allowlist secret
}

# Configure JWT
JWTHarmony.configure(
    User,
    JWTHarmonyConfig(
        secret_key='your-super-secret-key',  # pragma: allowlist secret
        token_location=frozenset({'headers', 'cookies'}),  # Support both
        access_token_expires=60 * 60,  # 1 hour for WebSocket connections
    ),
)


# WebSocket connection manager
class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: List[tuple[WebSocket, User]] = []

    async def connect(self, websocket: WebSocket, user: User) -> None:
        await websocket.accept()
        self.active_connections.append((websocket, user))
        await self.broadcast(f'{user.username} joined the chat', exclude_user=user)

    def disconnect(self, websocket: WebSocket) -> None:
        for connection in self.active_connections:
            if connection[0] == websocket:
                user = connection[1]
                self.active_connections.remove(connection)
                asyncio.create_task(self.broadcast(f'{user.username} left the chat', exclude_user=user))
                break

    async def send_personal_message(self, message: str, websocket: WebSocket) -> None:
        await websocket.send_text(message)

    async def broadcast(self, message: str, room: str | None = None, exclude_user: User | None = None) -> None:
        for websocket, user in self.active_connections:
            if room and user.room != room:
                continue
            if exclude_user and user.id == exclude_user.id:
                continue
            try:
                await websocket.send_text(message)
            except Exception:
                # Connection might be closed
                pass


manager = ConnectionManager()


# Exception handler
@app.exception_handler(JWTHarmonyException)
def authjwt_exception_handler(request: Request, exc: JWTHarmonyException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={'detail': exc.message})


def authenticate_user(username: str, password: str) -> User | None:
    """Authenticate user."""
    user_data = USERS_DB.get(username)
    if user_data and user_data['password'] == password:
        return User(**{k: v for k, v in user_data.items() if k != 'password'})
    return None


@app.post('/auth/login')
def login(credentials: LoginRequest, Authorize: JWTHarmony[User] = Depends(JWTHarmonyBare)) -> dict[str, Any]:
    """Login endpoint for getting JWT token."""
    user = authenticate_user(credentials.username, credentials.password)
    if not user:
        raise JWTHarmonyException(401, 'Invalid credentials')

    access_token = Authorize.create_access_token(user_claims=user)
    return {'access_token': access_token, 'token_type': 'bearer', 'user': user}


@app.websocket('/ws/token')
async def websocket_endpoint_token(
    websocket: WebSocket, token: str = Query(..., description='JWT access token'), Authorize: JWTHarmonyWS[User] = Depends(JWTHarmonyWebSocket)
) -> None:
    """
    WebSocket endpoint using token from query parameter.

    Connect with: ws://localhost:8000/ws/token?token=YOUR_JWT_TOKEN

    A URL is recorded where a header is not - proxy and server access logs, browser
    history, Referer - so the cookie-based endpoint below is the safer default, and a
    token passed this way should be short-lived.
    """
    try:
        # Authenticate using token from query parameter
        Authorize.jwt_required(token)
        user = Authorize.user_claims
        assert user is not None  # jwt_required guarantees user is not None

        await manager.connect(websocket, user)
        await manager.send_personal_message(f"Welcome {user.username}! You're in room: {user.room}", websocket)

        while True:
            # Receive message from WebSocket
            data = await websocket.receive_text()

            # Broadcast message to room
            message = f'{user.username}: {data}'
            await manager.broadcast(message, room=user.room)

    except JWTHarmonyException as e:
        await websocket.accept()
        await websocket.send_text(f'Authentication failed: {e.message}')
        await websocket.close()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.websocket('/ws/cookie')
async def websocket_endpoint_cookie(
    websocket: WebSocket, csrf_token: str = Query(..., description='CSRF token for cookie auth'), Authorize: JWTHarmonyWS[User] = Depends(JWTHarmonyWebSocket)
) -> None:
    """
    WebSocket endpoint using cookies for authentication.

    Requires login with cookies first, then connect with CSRF token.
    """
    try:
        # Set WebSocket for cookie-based auth
        Authorize.set_websocket(websocket)
        Authorize.set_csrf_token(csrf_token)

        # Authenticate using cookies
        Authorize.jwt_required()
        user = Authorize.user_claims
        assert user is not None  # jwt_required guarantees user is not None

        await manager.connect(websocket, user)
        await manager.send_personal_message(f'Welcome {user.username} (cookie auth)! Room: {user.room}', websocket)

        while True:
            data = await websocket.receive_text()
            message = f'{user.username} (cookie): {data}'
            await manager.broadcast(message, room=user.room)

    except JWTHarmonyException as e:
        await websocket.accept()
        await websocket.send_text(f'Authentication failed: {e.message}')
        await websocket.close()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.websocket('/ws/optional')
async def websocket_endpoint_optional(
    websocket: WebSocket, token: str | None = Query(None, description='Optional JWT token'), Authorize: JWTHarmonyWS[User] = Depends(JWTHarmonyWebSocket)
) -> None:
    """
    WebSocket endpoint with optional authentication.

    Allows both authenticated and anonymous users.
    """
    try:
        await websocket.accept()

        # Try to authenticate if token provided
        user = None
        if token:
            try:
                Authorize.jwt_optional(token)
                user = Authorize.user_claims
            except JWTHarmonyException:
                pass  # Continue as anonymous

        if user:
            await manager.send_personal_message(f'Welcome {user.username}! (authenticated)', websocket)
            username = user.username
        else:
            await manager.send_personal_message('Welcome anonymous user!', websocket)
            username = 'Anonymous'

        while True:
            data = await websocket.receive_text()
            message = f'{username}: {data}'
            await manager.broadcast(message)

    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get('/rooms')
def get_active_rooms(Authorize: JWTHarmony[User] = Depends(JWTHarmonyDep)) -> dict[str, Any]:
    """Get list of active rooms and users."""
    rooms: dict[str, list[str]] = {}
    for _, user in manager.active_connections:
        if user.room not in rooms:
            rooms[user.room] = []
        rooms[user.room].append(user.username)

    return {'rooms': rooms, 'total_connections': len(manager.active_connections)}


@app.get('/')
def get_chat_page() -> HTMLResponse:
    """Simple HTML page for testing WebSocket chat."""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>WebSocket Chat</title>
    </head>
    <body>
        <h1>WebSocket JWT Chat</h1>

        <div>
            <h3>Login</h3>
            <input type="text" id="username" placeholder="Username (alice or bob)">
            <input type="password" id="password" placeholder="Password (secret)">  <!-- pragma: allowlist secret -->
            <button onclick="login()">Login</button>
            <div id="loginResult"></div>
        </div>

        <div>
            <h3>Connect to WebSocket</h3>
            <button onclick="connectToken()">Connect with Token</button>
            <button onclick="connectOptional()">Connect Optional</button>
            <button onclick="disconnect()">Disconnect</button>
        </div>

        <div>
            <h3>Chat</h3>
            <input type="text" id="messageInput" placeholder="Type a message...">
            <button onclick="sendMessage()">Send</button>
            <div id="messages" style="height: 300px; overflow-y: scroll; border: 1px solid #ccc; padding: 10px;"></div>
        </div>

        <script>
            let ws = null;
            let token = null;

            async function login() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;

                try {
                    const response = await fetch('/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });

                    const data = await response.json();
                    if (response.ok) {
                        token = data.access_token;
                        document.getElementById('loginResult').textContent =
                            `Logged in as ${data.user.username} (${data.user.room})`;
                    } else {
                        document.getElementById('loginResult').textContent =
                            `Login failed: ${data.detail}`;
                    }
                } catch (error) {
                    document.getElementById('loginResult').textContent =
                        `Login error: ${error.message}`;
                }
            }

            function connectToken() {
                if (!token) {
                    alert('Please login first');
                    return;
                }

                ws = new WebSocket(`ws://localhost:8000/ws/token?token=${token}`);
                setupWebSocket();
            }

            function connectOptional() {
                const tokenParam = token ? `?token=${token}` : '';
                ws = new WebSocket(`ws://localhost:8000/ws/optional${tokenParam}`);
                setupWebSocket();
            }

            function setupWebSocket() {
                ws.onmessage = function(event) {
                    // textContent, never innerHTML: anyone on /ws/optional can broadcast markup.
                    appendMessage(event.data, false);
                };

                ws.onopen = function(event) {
                    addMessage('Connected to WebSocket');
                };

                ws.onclose = function(event) {
                    addMessage('Disconnected from WebSocket');
                };

                ws.onerror = function(error) {
                    addMessage('WebSocket error: ' + error);
                };
            }

            function sendMessage() {
                const input = document.getElementById('messageInput');
                if (ws && input.value) {
                    ws.send(input.value);
                    input.value = '';
                }
            }

            function disconnect() {
                if (ws) {
                    ws.close();
                    ws = null;
                }
            }

            function appendMessage(text, emphasised) {
                const messages = document.getElementById('messages');
                const line = document.createElement('div');
                const body = emphasised ? document.createElement('em') : line;
                body.textContent = text;
                if (emphasised) {
                    line.appendChild(body);
                }
                messages.appendChild(line);
                messages.scrollTop = messages.scrollHeight;
            }

            function addMessage(message) {
                appendMessage(message, true);
            }

            // Send message on Enter key
            document.getElementById('messageInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    sendMessage();
                }
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=8000)  # nosec


# Example usage:
# 1. Start the server:
#    python websocket_auth.py
#
# 2. Open browser and go to http://localhost:8000
#
# 3. Login with credentials:
#    - Username: alice, Password: secret (room: general)
#    - Username: bob, Password: secret (room: vip)
#
# 4. Connect to WebSocket and start chatting!
#
# Alternative command line testing:
# 1. Get token:
#    TOKEN=$(curl -s -X POST "http://localhost:8000/auth/login" \
#      -H "Content-Type: application/json" \
#      -d '{"username": "alice", "password": "secret"}' |  # pragma: allowlist secret \
#      jq -r '.access_token')
#
# 2. Connect with wscat:
#    wscat -c "ws://localhost:8000/ws/token?token=$TOKEN"
