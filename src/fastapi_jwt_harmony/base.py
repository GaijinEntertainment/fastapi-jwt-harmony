"""Base JWT authentication class with common token logic."""

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, ClassVar, Generic, Literal, Optional, TypeVar, Union, cast

import jwt
from pydantic import BaseModel

from .config import JWTHarmonyConfig
from .constants import ASYMMETRIC_ALGORITHMS, SYMMETRIC_ALGORITHMS
from .exceptions import (
    AccessTokenRequired,
    FreshTokenRequired,
    InvalidHeaderError,
    JWTDecodeError,
    MissingTokenError,
    RefreshTokenRequired,
    RevokedTokenError,
    TokenExpired,
)
from .utils import get_jwt_identifier

UserModelT = TypeVar('UserModelT', bound=BaseModel)


def _process_user_claims(user_claims: Optional[Union[dict[str, Any], BaseModel]]) -> dict[str, Any]:
    """Process user claims and extract subject if needed."""
    if user_claims is None:
        return {}

    if isinstance(user_claims, BaseModel):
        claims_dict = user_claims.model_dump()
    else:
        claims_dict = user_claims

    return claims_dict


def _validate_and_process_token_params(
    user_claims: Optional[Union[dict[str, Any], UserModelT]],
    subject: Optional[Union[str, int]],
) -> tuple[dict[str, Any], str]:
    """Validate and process token creation parameters."""
    # Validate user_claims type
    if user_claims is not None and not isinstance(user_claims, (dict, BaseModel)):
        raise TypeError('user_claims must be a Pydantic BaseModel or dict')

    # Handle user claims
    claims_dict = _process_user_claims(user_claims)
    final_subject = subject or claims_dict.get('id')

    if final_subject is None:
        raise TypeError('missing 1 required positional argument: subject or user_claims with id field')

    return claims_dict, str(final_subject)


class JWTHarmonyBase(Generic[UserModelT]):
    """
    Base JWT authentication class with common token logic.

    This abstract base class provides core JWT functionality that is shared
    between HTTP (FastAPI) and WebSocket implementations.
    """

    _config: Optional[JWTHarmonyConfig] = None
    _token_in_denylist_callback: Optional[Callable[[dict[str, Union[str, int, bool]]], bool]] = None
    _user_model_class: ClassVar[Optional[type[BaseModel]]] = None

    def __init__(self) -> None:
        """Initialize base JWT handler."""
        # Initialize instance variables
        self._token: Optional[str] = None

        # Ensure the class is configured
        if self._config is None:
            raise RuntimeError('JWTHarmony is not configured. Call JWTHarmony.configure() first.')

    @property
    def token(self) -> Optional[str]:
        """
        Returns the current JWT token if it has been extracted from the request.

        Returns:
            Optional[str]: The JWT token string if available, None otherwise.
        """
        return self._token

    @property
    def config(self) -> JWTHarmonyConfig:
        """
        Returns the configuration settings for JWT authentication.

        Returns:
            JWTHarmonyConfig: The configuration object containing all JWT settings.
        """
        if self._config is None:
            raise RuntimeError('JWTHarmony is not configured. Call JWTHarmony.configure() first.')
        return self._config

    @property
    def jwt_in_headers(self) -> bool:
        """
        Checks if the JWT is expected to be in the headers.

        Returns:
            bool: True if JWT is expected in headers, False otherwise.
        """
        return 'headers' in self.config.token_location

    @property
    def jwt_in_cookies(self) -> bool:
        """
        Checks if the JWT is expected to be in the cookies.

        Returns:
            bool: True if JWT is expected in cookies, False otherwise.
        """
        return 'cookies' in self.config.token_location

    @property
    def user_claims(self) -> Optional[UserModelT]:
        """
        Get user claims as a typed Pydantic model instance.

        Returns the user claims from the current JWT token as an instance
        of the configured user model type.

        Returns:
            Optional[UserModelT]: User model instance if token exists and is valid,
                                  None otherwise.
        """
        if not self._token or not self._user_model_class:
            return None

        try:
            decoded_token = self.get_raw_jwt()
            if not decoded_token:
                return None

            # Extract user claims (excluding JWT reserved claims)
            user_data = {k: v for k, v in decoded_token.items() if k not in {'sub', 'iat', 'nbf', 'jti', 'exp', 'fresh', 'type', 'csrf'}}

            # Create and return user model instance
            return cast(UserModelT, self._user_model_class(**user_data))  # pylint: disable=not-callable
        except (TypeError, ValueError):
            return None

    @classmethod
    def configure(
        cls,
        user_model_class: type[UserModelT],
        config: Optional[Union[JWTHarmonyConfig, dict[str, Any]]] = None,
        denylist_callback: Optional[Callable[[dict[str, Union[str, int, bool]]], bool]] = None,
    ) -> None:
        """
        Configure JWT authentication with a specific user model and optional config.

        Args:
            user_model_class: Pydantic model class for user claims
            config: JWT configuration (JWTHarmonyConfig instance or dict)
            denylist_callback: Optional function to check if token is denylisted
        """
        cls._user_model_class = user_model_class
        if config is not None:
            if isinstance(config, dict):
                cls._config = JWTHarmonyConfig(**config)
            else:
                cls._config = config
        if denylist_callback:
            cls._token_in_denylist_callback = denylist_callback

    def get_unverified_jwt(self, encoded_token: Optional[str] = None) -> Optional[dict[str, Union[str, int, bool]]]:
        """
        Decode a JWT token without signature or expiration verification.

        This method decodes a JWT token to extract its claims without validating
        the signature or checking if it has expired. Useful for extracting information
        from tokens that may be expired or when signature verification is not needed.

        Args:
            encoded_token: Encoded JWT as a string. If not provided, uses internal token.

        Returns:
            Decoded token payload if successful, None if no token is available.

        Raises:
            JWTDecodeError: If the token structure is invalid and cannot be decoded.
        """
        token = encoded_token or self._token
        if not token:
            return None

        try:
            decoded: dict[str, Union[str, int, bool]] = jwt.decode(token, options={'verify_signature': False, 'verify_exp': False})
            return decoded
        except jwt.DecodeError as e:
            raise JWTDecodeError(str(e)) from e

    def get_raw_jwt(self, encoded_token: Optional[str] = None) -> Optional[dict[str, Union[str, int, bool]]]:
        """
        Decodes and verifies a JSON Web Token (JWT).

        Args:
            encoded_token: Encoded JWT as a string. If not provided, uses internal token.

        Returns:
            The verified token if verification succeeds; otherwise, None.
        """
        token = encoded_token or self._token
        if not token:
            return None

        # Decode token without verification first to check if it's in denylist
        unverified_token = self.get_unverified_jwt(token)
        if not unverified_token:
            return None

        # Check if denylist is enabled
        if self.config.denylist_enabled:
            denylist_callback = self.__class__._token_in_denylist_callback  # pylint: disable=protected-access
            if not denylist_callback:
                raise RuntimeError('token_in_denylist_callback must be provided when denylist is enabled')

            # Check if we should check this token type
            token_type = unverified_token.get('type')
            if self.config.denylist_token_checks:
                # Only check if token type is in the check list
                if token_type in self.config.denylist_token_checks:
                    if denylist_callback(unverified_token):  # pylint: disable=not-callable
                        raise RevokedTokenError('Token has been revoked')
            elif denylist_callback(unverified_token):  # pylint: disable=not-callable
                # Check all token types if no specific types configured
                raise RevokedTokenError('Token has been revoked')

        # Now verify the token properly
        return self._verified_token(token)

    def get_jwt_subject(self) -> Optional[str]:
        """
        Get the subject (sub claim) from the current JWT token.

        Returns:
            Optional[str]: The subject claim if present, None otherwise.
        """
        decoded_token = self.get_raw_jwt()
        if decoded_token:
            sub = decoded_token.get('sub')
            return str(sub) if sub is not None else None
        return None

    def get_jti(self) -> Optional[str]:
        """
        Get the JWT ID (jti claim) from the current token.

        Returns:
            Optional[str]: The JWT ID if present, None otherwise.
        """
        decoded_token = self.get_raw_jwt()
        if decoded_token:
            jti = decoded_token.get('jti')
            return str(jti) if jti is not None else None
        return None

    def get_unverified_jwt_headers(self, encoded_token: Optional[str] = None) -> Optional[dict[str, Any]]:
        """
        Get headers from JWT without verification.

        Args:
            encoded_token: Encoded JWT. If not provided, uses current token.

        Returns:
            Dict of JWT headers if token exists, None otherwise.
        """
        token = encoded_token or self._token
        if not token:
            return None

        try:
            return jwt.get_unverified_header(token)
        except (jwt.DecodeError, jwt.InvalidTokenError):
            return None

    def create_access_token(
        self,
        subject: Optional[Union[str, int]] = None,
        fresh: Optional[bool] = False,
        algorithm: Optional[str] = None,
        headers: Optional[dict[str, Any]] = None,
        expires_time: Optional[Union[timedelta, int, bool]] = None,
        audience: Optional[Union[str, list[str]]] = None,
        user_claims: Optional[Union[dict[str, Any], UserModelT]] = None,
    ) -> str:
        """
        Create a new access token.

        Args:
            subject: JWT subject (usually user ID). Will be extracted from user_claims if not provided.
            fresh: Whether token should be marked as fresh (just logged in)
            algorithm: Algorithm to use for encoding (defaults to config)
            headers: Additional headers for the JWT
            expires_time: Token expiration time (timedelta, seconds, or False for no expiry)
            audience: JWT audience claim
            user_claims: Additional claims as dict or Pydantic model instance

        Returns:
            Encoded JWT access token
        """
        return self._create_token(
            subject=subject,
            fresh=fresh,
            type_token='access',
            expires_time=expires_time,
            algorithm=algorithm,
            headers=headers,
            audience=audience,
            user_claims=user_claims,
        )

    def create_refresh_token(
        self,
        subject: Optional[Union[str, int]] = None,
        algorithm: Optional[str] = None,
        headers: Optional[dict[str, Any]] = None,
        expires_time: Optional[Union[timedelta, int, bool]] = None,
        audience: Optional[Union[str, list[str]]] = None,
        user_claims: Optional[Union[dict[str, Any], UserModelT]] = None,
    ) -> str:
        """
        Create a new refresh token.

        Args:
            subject: JWT subject (usually user ID). Will be extracted from user_claims if not provided.
            algorithm: Algorithm to use for encoding (defaults to config)
            headers: Additional headers for the JWT
            expires_time: Token expiration time (timedelta, seconds, or False for no expiry)
            audience: JWT audience claim
            user_claims: Additional claims as dict or Pydantic model instance

        Returns:
            Encoded JWT refresh token
        """
        return self._create_token(
            subject=subject, type_token='refresh', expires_time=expires_time, algorithm=algorithm, headers=headers, audience=audience, user_claims=user_claims
        )

    def _create_token(
        self,
        subject: Optional[Union[str, int]] = None,
        fresh: Optional[bool] = False,
        type_token: Literal['access', 'refresh'] = 'access',
        expires_time: Optional[Union[timedelta, int, bool]] = None,
        algorithm: Optional[str] = None,
        headers: Optional[dict[str, Any]] = None,
        audience: Optional[Union[str, list[str]]] = None,
        user_claims: Optional[Union[dict[str, Any], UserModelT]] = None,
    ) -> str:
        """
        Internal method to create JWT tokens.

        This is the core token creation logic shared by access and refresh tokens.
        """
        # Validate and process input parameters
        claims_dict, final_subject = _validate_and_process_token_params(user_claims, subject)

        # Determine final algorithm and validate configuration
        final_algorithm = self._get_and_validate_algorithm(algorithm)

        # Calculate token expiration
        expire = self._calculate_token_expiration(expires_time, type_token)

        # Build and encode token
        payload = self._build_token_payload(final_subject, type_token, fresh, expire, audience, claims_dict)

        secret = self._get_secret_key(final_algorithm)
        return jwt.encode(payload, secret, algorithm=final_algorithm, headers=headers)

    def _get_and_validate_algorithm(self, algorithm: Optional[str]) -> str:
        """Get and validate the JWT algorithm."""
        final_algorithm = algorithm or self.config.algorithm

        # Validate asymmetric algorithm configuration
        if final_algorithm in ASYMMETRIC_ALGORITHMS and not self.config.private_key:
            raise RuntimeError('private_key must be set when using asymmetric algorithms')

        return final_algorithm

    def _calculate_token_expiration(self, expires_time: Optional[Union[timedelta, int, bool]], type_token: Literal['access', 'refresh']) -> Optional[datetime]:
        """Calculate token expiration time."""
        if expires_time is None:
            expires_time = self.config.access_token_expires if type_token == 'access' else self.config.refresh_token_expires

        if expires_time is False:
            return None

        if isinstance(expires_time, int):
            expires_time = timedelta(seconds=expires_time)

        return datetime.now(timezone.utc) + expires_time

    def _build_token_payload(
        self,
        subject: str,
        type_token: Literal['access', 'refresh'],
        fresh: Optional[bool],
        expire: Optional[datetime],
        audience: Optional[Union[str, list[str]]],
        claims_dict: dict[str, Any],
    ) -> dict[str, Any]:
        """Build the JWT token payload."""
        payload = {
            'sub': subject,
            'iat': datetime.now(timezone.utc),
            'nbf': datetime.now(timezone.utc),
            'jti': get_jwt_identifier(),
            'type': type_token,
        }

        # Add expiration if set
        if expire:
            payload['exp'] = expire

        # Add fresh flag for access tokens
        if type_token == 'access':
            payload['fresh'] = fresh

        # Add CSRF token for cookie-based auth
        if self.jwt_in_cookies and self.config.cookie_csrf_protect:
            payload['csrf'] = get_jwt_identifier()

        # Add audience if provided
        if audience:
            payload['aud'] = audience

        # Add issuer if configured
        if self.config.encode_issuer:
            payload['iss'] = self.config.encode_issuer

        # Merge user claims (excluding reserved claims)
        reserved_claims = {'sub', 'iat', 'nbf', 'jti', 'exp', 'type', 'fresh', 'csrf', 'aud', 'iss'}
        payload.update({k: v for k, v in claims_dict.items() if k not in reserved_claims})

        return payload

    def _get_secret_key(self, algorithm: str) -> str:
        """
        Get the appropriate secret key based on the algorithm.

        Args:
            algorithm: JWT algorithm

        Returns:
            Secret key for encoding/decoding
        """
        if algorithm in SYMMETRIC_ALGORITHMS:
            if not self.config.secret_key:
                raise RuntimeError('secret_key must be set to use HS256 algorithm')
            return self.config.secret_key

        # Asymmetric algorithm
        if not self.config.private_key:
            raise RuntimeError(f'private_key must be set to use {algorithm} algorithm')
        return self.config.private_key

    def _get_decode_key(self, algorithm: str) -> str:
        """
        Get the appropriate key for decoding based on the algorithm.

        Args:
            algorithm: JWT algorithm

        Returns:
            Key for decoding
        """
        if algorithm in SYMMETRIC_ALGORITHMS:
            if not self.config.secret_key:
                raise RuntimeError('secret_key must be set to decode HS256 tokens')
            return self.config.secret_key

        # Asymmetric algorithm - use public key for decoding
        if not self.config.public_key:
            raise RuntimeError(f'public_key must be set to decode {algorithm} tokens')
        return self.config.public_key

    def _verified_token(self, encoded_token: str) -> dict[str, Any]:
        """
        Verify and decode a JWT token.

        Args:
            encoded_token: The encoded JWT string

        Returns:
            Decoded token payload

        Raises:
            JWTDecodeError: If token is invalid
            TokenExpired: If token has expired
        """
        algorithms: list[str] = [self.config.algorithm]
        if self.config.decode_algorithms:
            algorithms = [alg for alg in self.config.decode_algorithms if alg is not None]

        try:
            # Get decode key for the algorithm
            unverified_headers = jwt.get_unverified_header(encoded_token)
            algorithm_from_header = unverified_headers.get('alg')
            final_algorithm = algorithm_from_header or self.config.algorithm
            secret = self._get_decode_key(final_algorithm)

            # Decode with all validations
            leeway = self.config.decode_leeway
            decoded: dict[str, Any] = jwt.decode(
                encoded_token,
                secret,
                algorithms=algorithms,
                audience=self.config.decode_audience,
                issuer=self.config.decode_issuer,
                leeway=leeway,
                options={'verify_aud': bool(self.config.decode_audience)},
            )
            return decoded
        except jwt.ExpiredSignatureError as exc:
            jti_value = (self.get_unverified_jwt(encoded_token) or {}).get('jti')
            raise TokenExpired('Token expired', jti=str(jti_value) if jti_value else None) from exc
        except jwt.InvalidTokenError as e:
            raise JWTDecodeError(str(e)) from e

    def _verify_jwt_in_request(self, token: str, type_token: str, token_from: str, fresh: Optional[bool] = False) -> None:
        """
        Verify JWT token from request.

        Args:
            token: JWT token to verify
            type_token: Expected token type value ('access' or 'refresh')
            token_from: Source of token (for error messages)
            fresh: Whether to require a fresh token

        Raises:
            Various JWT exceptions based on validation failures
        """
        if not token:
            raise MissingTokenError(f'Missing {type_token} token from {token_from}')

        # Verify token
        self._token = token
        decoded_token = self.get_raw_jwt()

        if not decoded_token:
            raise JWTDecodeError('Invalid token')

        # Check token type
        if decoded_token.get('type') != type_token:
            if type_token == 'access':
                raise AccessTokenRequired('Only access tokens are allowed')
            else:
                raise RefreshTokenRequired('Only refresh tokens are allowed')

        # Check freshness if required
        if fresh and not decoded_token.get('fresh', False):
            raise FreshTokenRequired('Fresh token required')

    def _get_jwt_from_headers(self, auth: str) -> str:
        """
        Extract JWT token from authorization header.

        Args:
            auth: Authorization header value

        Returns:
            Extracted token

        Raises:
            InvalidHeaderError: If header format is invalid
        """
        parts = auth.split()

        # Check for valid header format (should always be "Bearer <token>" or "JWT <token>" etc)
        if len(parts) != 2:
            header_name = self.config.header_name
            header_type = self.config.header_type
            raise InvalidHeaderError(f"Bad {header_name} header. Expected value '{header_type} <JWT>'")

        # Check that header type matches
        if parts[0] != self.config.header_type:
            header_name = self.config.header_name
            header_type = self.config.header_type
            raise InvalidHeaderError(f"Bad {header_name} header. Expected value '{header_type} <JWT>'")

        self._token = parts[1]
        return self._token
