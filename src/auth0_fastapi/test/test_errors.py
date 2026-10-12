from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth0_fastapi.errors import PasskeyError, PasskeyErrorCode, register_exception_handlers


def _client_raising(exc: Exception) -> TestClient:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/raise")
    async def raise_error():
        raise exc

    return TestClient(app)


class TestPasskeyErrorHandling:
    """Test how register_exception_handlers renders passkey errors."""

    def test_rate_limited_passkey_error_maps_to_429(self):
        """Test that too_many_requests becomes HTTP 429 so clients can back off."""
        client = _client_raising(
            PasskeyError(PasskeyErrorCode.TOO_MANY_REQUESTS, "Too many passkey signup requests")
        )

        res = client.get("/raise")

        assert res.status_code == 429
        assert res.json() == {"error": "too_many_requests", "message": "Too many passkey signup requests"}

    def test_retryable_passkey_error_body_omits_session_details(self):
        """Test that an unhandled retryable error never leaks auth_session into the response."""
        client = _client_raising(
            PasskeyError(
                PasskeyErrorCode.INVALID_GRANT,
                "Invalid or expired session",
                auth_session="sess_abc123",
                verification_required=["email"],
            )
        )

        res = client.get("/raise")

        assert res.status_code == 400
        assert res.json() == {"error": "invalid_grant", "message": "Invalid or expired session"}
        assert "sess_abc123" not in res.text

    def test_other_passkey_errors_map_to_400(self):
        """Test that non rate-limit passkey failures keep the default 400."""
        client = _client_raising(
            PasskeyError(PasskeyErrorCode.TOKEN_EXCHANGE_FAILED, "Passkey token exchange failed")
        )

        res = client.get("/raise")

        assert res.status_code == 400
        assert res.json()["error"] == "passkey_token_error"
