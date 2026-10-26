import pytest
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
        """Test that a PasskeyError with status_code 429 becomes HTTP 429 with Retry-After."""
        client = _client_raising(
            PasskeyError(
                PasskeyErrorCode.CHALLENGE_FAILED,
                "Passkey signup challenge failed with status 429",
                status_code=429,
                retry_after=30,
            )
        )

        res = client.get("/raise")

        assert res.status_code == 429
        assert res.headers["Retry-After"] == "30"
        assert res.json() == {
            "error": "passkey_challenge_error",
            "message": "Passkey signup challenge failed with status 429",
        }

    def test_rate_limited_passkey_error_without_retry_after_omits_header(self):
        """Test that a 429 without retry_after sends no Retry-After header."""
        client = _client_raising(
            PasskeyError(PasskeyErrorCode.TOKEN_EXCHANGE_FAILED, "Passkey token exchange failed", status_code=429)
        )

        res = client.get("/raise")

        assert res.status_code == 429
        assert "Retry-After" not in res.headers

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

    @pytest.mark.parametrize("auth0_status", [400, 401, 403, 404, 500, 502, 503])
    def test_passkey_error_relays_the_status_auth0_returned(self, auth0_status):
        """Test that a non rate-limit PasskeyError keeps the status Auth0 returned."""
        client = _client_raising(
            PasskeyError(
                PasskeyErrorCode.TOKEN_EXCHANGE_FAILED,
                "Passkey token exchange failed",
                status_code=auth0_status,
            )
        )

        res = client.get("/raise")

        assert res.status_code == auth0_status
        assert res.json() == {"error": "passkey_token_error", "message": "Passkey token exchange failed"}
        assert "Retry-After" not in res.headers

    def test_passkey_error_without_http_status_maps_to_400(self):
        """Test that a PasskeyError with no Auth0 response keeps the default 400."""
        client = _client_raising(
            PasskeyError(
                PasskeyErrorCode.CHALLENGE_FAILED,
                "Passkey login challenge failed",
                ConnectionError("connection refused"),
            )
        )

        res = client.get("/raise")

        assert res.status_code == 400
        assert res.json()["error"] == "passkey_challenge_error"

    @pytest.mark.parametrize("auth0_status", [200, 302, 600])
    def test_passkey_error_with_a_non_error_status_maps_to_400(self, auth0_status):
        """Test that only 400 to 599 is relayed, so a stray 2xx or 3xx cannot reach the browser."""
        client = _client_raising(
            PasskeyError(
                PasskeyErrorCode.TOKEN_EXCHANGE_FAILED,
                "Passkey token exchange failed",
                status_code=auth0_status,
            )
        )

        res = client.get("/raise")

        assert res.status_code == 400
