from typing import Optional

#Imported from auth0-server-python
from auth0_server_python.error import (
    AccessTokenError,
    AccessTokenForConnectionError,
    ApiError,
    Auth0Error,
    BackchannelLogoutError,
    CustomTokenExchangeError,
    CustomTokenExchangeErrorCode,
    InvalidArgumentError,
    IssuerValidationError,
    MissingRequiredArgumentError,
    MissingTransactionError,
    PasskeyError,
    PasskeyErrorCode,
)
from fastapi import Request
from fastapi.responses import JSONResponse


class ConfigurationError(Auth0Error):
    """
    Error raised when an invalid configuration is used.
    """
    code = "configuration_error"

    def __init__(self, message=None):
        super().__init__(message or "An invalid configuration was provided.")
        self.name = "ConfigurationError"

def _passkey_error_response(exc: PasskeyError) -> tuple[int, Optional[dict[str, str]]]:
    """Return the HTTP status and headers for a PasskeyError, relaying the status Auth0 returned."""
    if exc.status_code == 429:
        headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after is not None else None
        return 429, headers
    if exc.status_code is not None and 400 <= exc.status_code <= 599:
        return exc.status_code, None
    return 400, None

def auth0_exception_handler(request: Request, exc: Auth0Error):
    """
    Exception handler for Auth0 SDK errors.
    Maps different Auth0 errors to appropriate HTTP status codes.
    """
    # Set a default status code
    status_code = 400
    headers = None

    if isinstance(exc, MissingTransactionError):
        status_code = 404  # Not Found
    elif isinstance(exc, MissingRequiredArgumentError):
        status_code = 422  # Unprocessable Entity
    elif isinstance(exc, IssuerValidationError):
        status_code = 401  # Unauthorized - token issuer mismatch
    elif isinstance(exc, ApiError):
        status_code = 502  # Bad Gateway, indicates an upstream error
    elif isinstance(exc, AccessTokenError):
        status_code = 401  # Unauthorized
    elif isinstance(exc, BackchannelLogoutError):
        status_code = 400  # Bad Request
    elif isinstance(exc, AccessTokenForConnectionError):
        status_code = 400  # Bad Request
    elif isinstance(exc, PasskeyError):
        status_code, headers = _passkey_error_response(exc)

    return JSONResponse(
        status_code=status_code,
        headers=headers,
        content={
            "error": getattr(exc, "code", "auth_error"),
            "message": exc.message or "An authentication error occurred.",
        },
    )

def register_exception_handlers(app):
    """
    Register all Auth0-related exception handlers with the FastAPI app.
    """
    app.add_exception_handler(Auth0Error, auth0_exception_handler)
