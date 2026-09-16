"""HTTP (FastAPI) JWT authentication implementation."""

import hmac
from datetime import timedelta
from typing import Literal, Optional, Union

from fastapi import Request, Response

from .base import JWTHarmonyBase, UserModelT
from .exceptions import AccessTokenRequired, CSRFError, InvalidHeaderError, JWTDecodeError, JWTHarmonyException, MissingTokenError, RevokedTokenError


class JWTHarmony(JWTHarmonyBase[UserModelT]):
    """
    HTTP-specific JWT authentication implementation for FastAPI.

    This class handles JWT authentication for regular HTTP requests
    with support for both header and cookie-based authentication.
    """

    def __init__(self, req: Optional[Request] = None, res: Optional[Response] = None) -> None:
        """
        Initialize HTTP JWT handler.

        Args:
            req: The incoming FastAPI request object
            res: The outgoing FastAPI response object
        """
        super().__init__()
        self._request = req
        self._response = res

        # Extract token from headers if present
        if req and self.jwt_in_headers:
            if auth := req.headers.get(self.config.header_name):
                try:
                    self._get_jwt_from_headers(auth)
                except InvalidHeaderError:
                    # When cookies are also enabled, a malformed Authorization
                    # header must not block cookie authentication; defer to it.
                    if not self.jwt_in_cookies:
                        raise

    def _authenticate(self, type_token: str, cookie_key: str, csrf_header_name: str, fresh: bool = False) -> None:
        """
        Verify a token from the configured locations, trying headers then cookies.

        A header token that fails verification falls back to cookies when cookies
        are enabled, but its specific error (e.g. TokenExpired with its jti) is
        surfaced if the cookie location has no token to try. Revoked tokens are a
        definitive rejection and never fall back.
        """
        header_error: Optional[JWTHarmonyException] = None

        if self.jwt_in_headers:
            if self.token:
                try:
                    self._verify_jwt_in_request(self.token, type_token, 'headers', fresh)
                    return  # Success
                except RevokedTokenError:
                    raise
                except JWTHarmonyException as exc:
                    if not self.jwt_in_cookies:
                        raise  # No other location to try
                    header_error = exc
            elif not self.jwt_in_cookies:
                raise MissingTokenError(f'Missing {self.config.header_name} Header')

        if self.jwt_in_cookies:
            if self._request is None:
                raise RuntimeError('Request object is required for cookie authentication')
            try:
                self._verify_and_get_jwt_in_cookies(self._request, cookie_key, csrf_header_name, type_token, fresh)
            except MissingTokenError:
                # Nothing usable in cookies either; prefer the header's specific error.
                if header_error is not None:
                    raise header_error from None
                raise

    def jwt_required(self) -> None:
        """
        Verify that a valid access token is present in the request.

        Checks both headers and cookies based on configuration.

        Raises:
            MissingTokenError: If no token is found
            Various JWT exceptions on validation failure
        """
        self._authenticate('access', self.config.access_cookie_key, self.config.access_csrf_header_name)

    def jwt_optional(self) -> None:
        """
        Optionally verify JWT token if present in the request.

        Does not raise exceptions if token is missing or invalid, except for revoked tokens.
        """
        # Try headers first if enabled
        if self.jwt_in_headers and self.token:
            try:
                self._verify_jwt_in_request(self.token, 'access', 'headers')
                return  # Success
            except (RevokedTokenError, AccessTokenRequired):
                # Always raise for revoked tokens and wrong token types, even in optional mode
                raise
            except JWTHarmonyException:
                # For optional, we don't raise other exceptions
                self._token = None

        # Try cookies if enabled
        if self.jwt_in_cookies and self._request:
            self._verify_and_get_jwt_optional_in_cookies(self._request)

    def jwt_refresh_token_required(self) -> None:
        """
        Verify that a valid refresh token is present in the request.

        Checks both headers and cookies based on configuration.

        Raises:
            MissingTokenError: If no token is found
            RefreshTokenRequired: If token is not a refresh token
            Various JWT exceptions on validation failure
        """
        self._authenticate('refresh', self.config.refresh_cookie_key, self.config.refresh_csrf_header_name)

    def fresh_jwt_required(self) -> None:
        """
        Verify that a valid fresh access token is present in the request.

        Checks both headers and cookies based on configuration.

        Raises:
            MissingTokenError: If no token is found
            FreshTokenRequired: If token is not fresh
            Various JWT exceptions on validation failure
        """
        self._authenticate('access', self.config.access_cookie_key, self.config.access_csrf_header_name, fresh=True)

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
        csrf_path: Optional[str] = None,
    ) -> None:
        """
        Set access token cookies with optional CSRF protection.

        Args:
            encoded_access_token: The encoded JWT access token
            response: Optional response object (uses instance response if not provided)
            max_age: Optional max age for the cookie in seconds
            key: Cookie name for this call, in place of `access_cookie_key`
            path: Cookie path for this call, in place of `access_cookie_path`
            domain: Cookie domain for this call, in place of `cookie_domain`; it covers the CSRF cookie too, the two belonging to one site
            samesite: SameSite for this call, in place of `cookie_samesite`; it covers the CSRF cookie too
            csrf_key: CSRF cookie name for this call, in place of `access_csrf_cookie_key`
            csrf_path: CSRF cookie path for this call, in place of `access_csrf_cookie_path`

        Raises:
            ValueError: If `samesite` is 'none' while `cookie_secure` is False, a combination browsers reject
        """
        response = response or self._response
        if not response:
            raise RuntimeError('Response object is required to set cookies')

        # Calculate max_age from access token expiration if not provided
        if max_age is None:
            max_age = self._get_cookie_max_age(self.config.access_token_expires)

        # Set main access token cookie
        cookie_key = key if key is not None else self.config.access_cookie_key
        cookie_path = path if path is not None else self.config.access_cookie_path
        cookie_domain = domain if domain is not None else self.config.cookie_domain
        cookie_samesite = self._resolve_samesite(samesite)
        response.set_cookie(
            key=cookie_key,
            value=encoded_access_token,
            max_age=max_age,
            path=cookie_path,
            domain=cookie_domain,
            secure=self.config.cookie_secure,
            httponly=True,
            samesite=cookie_samesite,
        )

        # Set CSRF cookie if protection is enabled
        if self.config.cookie_csrf_protect:
            self._set_csrf_cookie(
                encoded_access_token,
                response,
                csrf_key if csrf_key is not None else self.config.access_csrf_cookie_key,
                csrf_path if csrf_path is not None else self.config.access_csrf_cookie_path,
                cookie_domain,
                cookie_samesite,
                max_age,
            )

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
        csrf_path: Optional[str] = None,
    ) -> None:
        """
        Set refresh token cookies with optional CSRF protection.

        Args:
            encoded_refresh_token: The encoded JWT refresh token
            response: Optional response object (uses instance response if not provided)
            max_age: Optional max age for the cookie in seconds
            key: Cookie name for this call, in place of `refresh_cookie_key`
            path: Cookie path for this call, in place of `refresh_cookie_path`
            domain: Cookie domain for this call, in place of `cookie_domain`; it covers the CSRF cookie too, the two belonging to one site
            samesite: SameSite for this call, in place of `cookie_samesite`; it covers the CSRF cookie too
            csrf_key: CSRF cookie name for this call, in place of `refresh_csrf_cookie_key`
            csrf_path: CSRF cookie path for this call, in place of `refresh_csrf_cookie_path`

        Raises:
            ValueError: If `samesite` is 'none' while `cookie_secure` is False, a combination browsers reject
        """
        response = response or self._response
        if not response:
            raise RuntimeError('Response object is required to set cookies')

        # Calculate max_age from refresh token expiration if not provided
        if max_age is None:
            max_age = self._get_cookie_max_age(self.config.refresh_token_expires)

        # Set main refresh token cookie
        cookie_key = key if key is not None else self.config.refresh_cookie_key
        cookie_path = path if path is not None else self.config.refresh_cookie_path
        cookie_domain = domain if domain is not None else self.config.cookie_domain
        cookie_samesite = self._resolve_samesite(samesite)
        response.set_cookie(
            key=cookie_key,
            value=encoded_refresh_token,
            max_age=max_age,
            path=cookie_path,
            domain=cookie_domain,
            secure=self.config.cookie_secure,
            httponly=True,
            samesite=cookie_samesite,
        )

        # Set CSRF cookie if protection is enabled
        if self.config.cookie_csrf_protect:
            self._set_csrf_cookie(
                encoded_refresh_token,
                response,
                csrf_key if csrf_key is not None else self.config.refresh_csrf_cookie_key,
                csrf_path if csrf_path is not None else self.config.refresh_csrf_cookie_path,
                cookie_domain,
                cookie_samesite,
                max_age,
            )

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
        refresh_csrf_path: Optional[str] = None,
    ) -> None:
        """
        Unset all JWT cookies (access, refresh, and CSRF).

        A cookie is cleared only where it was set, so a call that named a cookie must name it here too. The access and refresh halves are named
        separately, because a scoped application gives them paths of their own.

        Args:
            response: Optional response object (uses instance response if not provided)
            access_key: Access cookie name for this call, in place of `access_cookie_key`
            access_path: Access cookie path for this call, in place of `access_cookie_path`
            access_domain: Access cookie domain for this call, in place of `cookie_domain`; it covers that half's CSRF cookie too
            access_csrf_key: Access CSRF cookie name for this call, in place of `access_csrf_cookie_key`
            access_csrf_path: Access CSRF cookie path for this call, in place of `access_csrf_cookie_path`
            refresh_key: Refresh cookie name for this call, in place of `refresh_cookie_key`
            refresh_path: Refresh cookie path for this call, in place of `refresh_cookie_path`
            refresh_domain: Refresh cookie domain for this call, in place of `cookie_domain`; it covers that half's CSRF cookie too
            refresh_csrf_key: Refresh CSRF cookie name for this call, in place of `refresh_csrf_cookie_key`
            refresh_csrf_path: Refresh CSRF cookie path for this call, in place of `refresh_csrf_cookie_path`
        """
        self.unset_access_cookies(response, key=access_key, path=access_path, domain=access_domain, csrf_key=access_csrf_key, csrf_path=access_csrf_path)
        self.unset_refresh_cookies(response, key=refresh_key, path=refresh_path, domain=refresh_domain, csrf_key=refresh_csrf_key, csrf_path=refresh_csrf_path)

    def unset_access_cookies(
        self,
        response: Optional[Response] = None,
        *,
        key: Optional[str] = None,
        path: Optional[str] = None,
        domain: Optional[str] = None,
        csrf_key: Optional[str] = None,
        csrf_path: Optional[str] = None,
    ) -> None:
        """
        Unset access token cookies.

        A cookie is cleared only where it was set, so a call that named a cookie must name it here too.

        Args:
            response: Optional response object (uses instance response if not provided)
            key: Cookie name for this call, in place of `access_cookie_key`
            path: Cookie path for this call, in place of `access_cookie_path`
            domain: Cookie domain for this call, in place of `cookie_domain`; it covers the CSRF cookie too, the two belonging to one site
            csrf_key: CSRF cookie name for this call, in place of `access_csrf_cookie_key`
            csrf_path: CSRF cookie path for this call, in place of `access_csrf_cookie_path`
        """
        response = response or self._response
        if not response:
            raise RuntimeError('Response object is required to unset cookies')

        # Unset main access token cookie
        cookie_key = key if key is not None else self.config.access_cookie_key
        cookie_path = path if path is not None else self.config.access_cookie_path
        cookie_domain = domain if domain is not None else self.config.cookie_domain
        response.delete_cookie(
            key=cookie_key,
            path=cookie_path,
            domain=cookie_domain,
            secure=self.config.cookie_secure,
            samesite=self.config.cookie_samesite,
        )

        # Unset CSRF cookie
        response.delete_cookie(
            key=csrf_key if csrf_key is not None else self.config.access_csrf_cookie_key,
            path=csrf_path if csrf_path is not None else self.config.access_csrf_cookie_path,
            domain=cookie_domain,
            secure=self.config.cookie_secure,
            samesite=self.config.cookie_samesite,
        )

    def unset_refresh_cookies(
        self,
        response: Optional[Response] = None,
        *,
        key: Optional[str] = None,
        path: Optional[str] = None,
        domain: Optional[str] = None,
        csrf_key: Optional[str] = None,
        csrf_path: Optional[str] = None,
    ) -> None:
        """
        Unset refresh token cookies.

        A cookie is cleared only where it was set, so a call that named a cookie must name it here too.

        Args:
            response: Optional response object (uses instance response if not provided)
            key: Cookie name for this call, in place of `refresh_cookie_key`
            path: Cookie path for this call, in place of `refresh_cookie_path`
            domain: Cookie domain for this call, in place of `cookie_domain`; it covers the CSRF cookie too, the two belonging to one site
            csrf_key: CSRF cookie name for this call, in place of `refresh_csrf_cookie_key`
            csrf_path: CSRF cookie path for this call, in place of `refresh_csrf_cookie_path`
        """
        response = response or self._response
        if not response:
            raise RuntimeError('Response object is required to unset cookies')

        # Unset main refresh token cookie
        cookie_key = key if key is not None else self.config.refresh_cookie_key
        cookie_path = path if path is not None else self.config.refresh_cookie_path
        cookie_domain = domain if domain is not None else self.config.cookie_domain
        response.delete_cookie(
            key=cookie_key,
            path=cookie_path,
            domain=cookie_domain,
            secure=self.config.cookie_secure,
            samesite=self.config.cookie_samesite,
        )

        # Unset CSRF cookie
        response.delete_cookie(
            key=csrf_key if csrf_key is not None else self.config.refresh_csrf_cookie_key,
            path=csrf_path if csrf_path is not None else self.config.refresh_csrf_cookie_path,
            domain=cookie_domain,
            secure=self.config.cookie_secure,
            samesite=self.config.cookie_samesite,
        )

    def _resolve_samesite(self, samesite: Optional[Literal['strict', 'lax', 'none']]) -> Optional[Literal['strict', 'lax', 'none']]:
        """
        Resolve a per-call SameSite against the configuration.

        Args:
            samesite: The SameSite value for this call, or None to take the configured one

        Returns:
            The SameSite value to write on the cookie

        Raises:
            ValueError: If 'none' is asked for while `cookie_secure` is False, a combination browsers reject
        """
        if samesite is None:
            return self.config.cookie_samesite
        if samesite == 'none' and not self.config.cookie_secure:
            raise ValueError("cookie_secure must be True when samesite is 'none'")
        return samesite

    def _set_csrf_cookie(
        self,
        encoded_token: str,
        response: Response,
        cookie_key: str,
        cookie_path: str,
        cookie_domain: Optional[str],
        cookie_samesite: Optional[Literal['strict', 'lax', 'none']],
        max_age: Optional[int],
    ) -> None:
        """
        Set CSRF protection cookie.

        Args:
            encoded_token: The encoded JWT token
            response: Response object to set cookie on
            cookie_key: The CSRF cookie key to use
            cookie_path: The cookie path to use
            cookie_domain: The cookie domain to use, already resolved against the configuration
            cookie_samesite: The SameSite value to use, already resolved against the configuration
            max_age: Max age for the cookie in seconds (None if no expiration)
        """
        # Decode token to get CSRF value
        decoded = self.get_raw_jwt(encoded_token)
        if not decoded or 'csrf' not in decoded:
            return

        csrf_value = decoded['csrf']

        # Set CSRF cookie (not httponly so JS can read it)
        response.set_cookie(
            key=cookie_key,
            value=str(csrf_value),
            max_age=max_age,
            path=cookie_path,
            domain=cookie_domain,
            secure=self.config.cookie_secure,
            httponly=False,  # Must be False for CSRF
            samesite=cookie_samesite,
        )

    def _verify_and_get_jwt_in_cookies(self, request: Request, cookie_key: str, csrf_header_name: str, type_token: str, fresh: bool = False) -> None:
        """
        Verify and extract JWT from cookies with CSRF protection.

        Args:
            request: The request object containing cookies
            cookie_key: The cookie key to look for
            csrf_header_name: The CSRF header name to check
            type_token: Expected token type value ('access' or 'refresh')
            fresh: Whether to require a fresh token
        """
        # Extract token from cookies
        cookie = request.cookies.get(cookie_key)
        if not cookie:
            raise MissingTokenError(f'Missing cookie {cookie_key}')

        # Check CSRF protection if enabled
        if self.config.cookie_csrf_protect:
            # Check if method requires CSRF
            if request.method in self.config.csrf_methods:
                # Get CSRF token from header
                csrf_token = request.headers.get(csrf_header_name)
                if not csrf_token:
                    raise CSRFError('Missing CSRF Token')

                # Verify token and get CSRF from it
                self._token = cookie
                self._verify_jwt_in_request(self._token, type_token, 'cookies', fresh)

                decoded_token = self.get_raw_jwt()
                if decoded_token:
                    csrf_in_token = decoded_token.get('csrf')
                    if not csrf_in_token:
                        raise JWTDecodeError('Missing claim: csrf')

                    # Compare CSRF tokens

                    if not hmac.compare_digest(str(csrf_in_token), str(csrf_token)):
                        raise CSRFError('CSRF double submit tokens do not match')
            else:
                # Method doesn't require CSRF, just verify token
                self._token = cookie
                self._verify_jwt_in_request(self._token, type_token, 'cookies', fresh)
        else:
            # No CSRF protection, just verify token
            self._token = cookie
            self._verify_jwt_in_request(self._token, type_token, 'cookies', fresh)

    def _verify_and_get_jwt_optional_in_cookies(self, request: Request) -> None:
        """
        Optionally verify JWT from cookies.

        Does not raise exceptions if token is missing or invalid.

        Args:
            request: The request object containing cookies
        """
        # Try to get access token from cookies
        cookie_key = self.config.access_cookie_key
        cookie = request.cookies.get(cookie_key)

        if not cookie:
            # No token, but that's OK for optional
            return

        try:
            # Check CSRF if enabled and method requires it
            if self.config.cookie_csrf_protect and request.method in self.config.csrf_methods:
                csrf_header_name = self.config.access_csrf_header_name
                csrf_token = request.headers.get(csrf_header_name)

                if not csrf_token:
                    # No CSRF token, treat as no auth
                    return

                # Verify token
                self._token = cookie
                self._verify_jwt_in_request(self._token, 'access', 'cookies')

                # Verify CSRF
                decoded_token = self.get_raw_jwt()
                if decoded_token:
                    csrf_in_token = decoded_token.get('csrf')
                    if not csrf_in_token:
                        # No CSRF in token, treat as no auth
                        self._token = None
                        return

                    if not hmac.compare_digest(str(csrf_in_token), str(csrf_token)):
                        # CSRF mismatch, treat as no auth
                        self._token = None
                        return
            else:
                # No CSRF protection or method doesn't require it
                self._token = cookie
                self._verify_jwt_in_request(self._token, 'access', 'cookies')
        except (RevokedTokenError, AccessTokenRequired):
            # Always raise for revoked tokens and wrong token types, even in optional mode
            raise
        except JWTHarmonyException:
            # For optional, we don't raise other exceptions
            self._token = None

    @staticmethod
    def _get_cookie_max_age(expires: Union[bool, int, timedelta]) -> Optional[int]:
        """
        Convert token expiration configuration to cookie max_age.

        Args:
            expires: Token expiration time (timedelta, seconds as int, or False for no expiry)

        Returns:
            Max age in seconds for cookie, or None if token doesn't expire
        """
        if expires is False:
            return None

        if isinstance(expires, bool):
            # Should not happen due to validation, but handle it
            return None

        if isinstance(expires, timedelta):
            return int(expires.total_seconds())

        # It's already an int (seconds)
        return expires
