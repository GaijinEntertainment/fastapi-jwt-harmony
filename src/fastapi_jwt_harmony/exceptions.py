"""Exception classes for JWT authentication."""


class JWTHarmonyException(Exception):
    """
    Custom exception class for AuthJWT.

    This class is a custom exception specifically for handling errors and
    exceptions that arise within the AuthJWT system. It extends the base
    Exception class to provide specialized error handling for authentication
    and token-related operations.

    Attributes:
        status_code (int): HTTP status code associated with the error.
        message (str): Error message describing the exception.
    """

    def __init__(self, status_code: int, message: str) -> None:
        """
        Initialize the JWT Harmony exception.

        Args:
            status_code (int): HTTP status code for the error.
            message (str): Error message describing the exception.
        """
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class InvalidHeaderError(JWTHarmonyException):
    """
    Exception raised for invalid header errors.

    This class is used to handle exceptions related to invalid headers. It inherits
    from `JWTHarmonyException` and provides a way to define a specific status code and
    message when an invalid header error occurs.

    Attributes:
        status_code (int): HTTP status code representing the error (422).
        message (str): Description of the error.
    """

    def __init__(self, message: str) -> None:
        """
        Represents an invalid header error with a descriptive message.

        Args:
            message (str): A descriptive message about the invalid header error.
        """
        super().__init__(422, message)


class JWTDecodeError(JWTHarmonyException):
    """
    Represents an exception raised during the decoding of a JWT token.

    This exception is used to indicate issues specifically related to
    the decoding of a JSON Web Token (JWT), typically involving invalid
    token structure or contents. It extends from the JWTHarmonyException
    class to provide context and additional attributes for handling
    such errors.

    Attributes:
        status_code (int): The HTTP status code associated with the error (422).
        message (str): A detailed message providing information about
            the decoding error.
    """

    def __init__(self, message: str) -> None:
        """
        Initializes a JWT decode error with a message.

        Args:
            message (str): A string providing a message or description of the JWT decode error.
        """
        super().__init__(422, message)


class CSRFError(JWTHarmonyException):
    """
    Represents an error raised when a CSRF validation fails.

    This class is a specific exception for handling cases where a CSRF token is
    invalid or missing. It is derived from JWTHarmonyException, allowing it to be
    used within contexts that deal specifically with authentication-related
    errors.

    Attributes:
        status_code (int): The HTTP status code associated with the error (401).
        message (str): The error message describing the CSRF error.
    """

    def __init__(self, message: str) -> None:
        """
        Initializes a CSRF error with a message.

        Args:
            message (str): Message describing the CSRF validation error.
        """
        super().__init__(401, message)


class MissingTokenError(JWTHarmonyException):
    """
    Exception raised when a token is missing in an authentication process.

    This class is a specific type of authentication error, intended to indicate
    that a required token is absent. It provides information about the HTTP
    status code and a message detailing the error.

    Attributes:
        status_code (int): The HTTP status code associated with the error (401).
        message (str): A descriptive message providing details about the error.
    """

    def __init__(self, message: str) -> None:
        """
        Initializes a missing token error with a message.

        Args:
            message (str): Message providing details about the missing token error.
        """
        super().__init__(401, message)


class RevokedTokenError(JWTHarmonyException):
    """
    Represents an error indicating that a token has been revoked.

    This class extends the `JWTHarmonyException` base class for handling exceptions
    in token-based authentication systems. It is typically used to signal that
    a token presented for authentication or other purposes has been invalidated
    and is no longer valid. The exception contains a status code corresponding
    to the error and a message explaining the reason for the token invalidation.

    Attributes:
        status_code (int): The HTTP status code representing the error (401).
        message (str): A descriptive message providing details about the error.
    """

    def __init__(self, message: str) -> None:
        """
        Initializes a revoked token error with a message.

        Args:
            message (str): A descriptive message providing details about the revoked token error.
        """
        super().__init__(401, message)


class AccessTokenRequired(JWTHarmonyException):
    """
    Represents an exception that indicates an access token is required.

    This exception is raised when an operation requires an access token, and it
    has not been provided or is invalid. It serves as a mechanism to enforce
    token-based authentication in applications where secure access control
    is critical.

    Attributes:
        status_code (int): The HTTP status code associated with the exception (422).
        message (str): A detailed message describing the reason for the exception.
    """

    def __init__(self, message: str) -> None:
        """
        Initializes an access token required error with a message.

        Args:
            message (str): A message describing why an access token is required.
        """
        super().__init__(422, message)


class RefreshTokenRequired(JWTHarmonyException):
    """
    Exception raised when a refresh token is required.

    This exception is intended to handle cases where a refresh token is necessary
    for authentication-related scenarios. It encapsulates a status code and an
    associated message, providing detailed information about the exception.

    Attributes:
        status_code (int): The HTTP status code associated with the exception (422).
        message (str): A detailed message explaining the exception.
    """

    def __init__(self, message: str) -> None:
        """
        Initializes a refresh token required error with a message.

        Args:
            message (str): A descriptive message explaining why a refresh token is required.
        """
        super().__init__(422, message)


class FreshTokenRequired(JWTHarmonyException):
    """
    Exception raised when a fresh token is required.

    This exception is specifically used to indicate that an action or request
    requires a fresh token for security purposes. It inherits from
    `JWTHarmonyException` to maintain consistency with related exceptions.

    Attributes:
        status_code (int): The HTTP status code associated with this exception (401).
        message (str): The error message providing details about the exception.
    """

    def __init__(self, message: str) -> None:
        """
        Initializes a fresh token required error with a message.

        Args:
            message (str): The message explaining why a fresh token is required.
        """
        super().__init__(401, message)


class TokenExpired(JWTHarmonyException):
    """
    Exception raised when a token has expired.

    This class is used to indicate that a token has passed its expiration time
    and can no longer be considered valid. It details the status code and a
    message describing the exception.

    Attributes:
        status_code (int): HTTP status code corresponding to the exception (401).
        message (str): Description or message explaining the reason for the
            exception.
        jti (str | None): The JWT ID (jti claim) of the expired token, if available.
    """

    def __init__(self, message: str, jti: str | None = None) -> None:
        """Initializes a token expired error with a message.

        Args:
            message (str): The message explaining that the token has expired.
            jti (str | None): The JWT ID (jti claim) of the expired token, if available.
        """
        super().__init__(401, message)
        self.jti = jti
