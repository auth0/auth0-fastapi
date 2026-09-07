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
)
from fastapi import Request
from fastapi.responses import JSONResponse


class ConfigurationError(Auth0Error):
    """Invalid SDK configuration."""

    code = "configuration_error"

    def __init__(self, message=None):
        super().__init__(message or "Invalid SDK configuration.")
        self.name = "ConfigurationError"

def auth0_exception_handler(request: Request, exc: Auth0Error):
    """Maps Auth0 SDK errors to HTTP status codes."""
    status_code = 400

    if isinstance(exc, MissingTransactionError):
        status_code = 404
    elif isinstance(exc, MissingRequiredArgumentError):
        status_code = 422
    elif isinstance(exc, IssuerValidationError):
        status_code = 401
    elif isinstance(exc, ApiError):
        status_code = 502
    elif isinstance(exc, AccessTokenError):
        status_code = 401
    elif isinstance(exc, BackchannelLogoutError):
        status_code = 400
    elif isinstance(exc, AccessTokenForConnectionError):
        status_code = 400

    return JSONResponse(
        status_code=status_code,
        content={
            "error": getattr(exc, "code", "auth_error"),
            "message": exc.message or "An authentication error occurred.",
        },
    )

def register_exception_handlers(app):
    """Registers the Auth0 exception handler with the FastAPI app."""
    app.add_exception_handler(Auth0Error, auth0_exception_handler)
