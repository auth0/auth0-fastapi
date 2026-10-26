import json
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from auth0_server_python.auth_types import PasskeyAuthResponse
from auth0_server_python.error import MfaRequiredError, MfaVerifyError
from fastapi import Request, Response
from jwcrypto import jwk

from auth0_fastapi.auth.auth_client import AuthClient
from auth0_fastapi.config import Auth0Config

DOMAIN = "test.auth0.com"
CLIENT_ID = "test_client_id"
AUDIENCE = "https://api.example.com"
RAW_MFA_TOKEN = "raw-mfa-token-issued-by-auth0"
SCOPE = "openid profile email offline_access"


class MockAuth0:
    """Answers the Auth0 endpoints the passkey sign-in and MFA verification call."""

    def __init__(self, signing_key):
        self.signing_key = signing_key
        self.token_responses = []
        self.token_requests = []

    def id_token(self):
        now = int(time.time())
        claims = {
            "iss": f"https://{DOMAIN}/",
            "aud": CLIENT_ID,
            "sub": "auth0|abc123",
            "iat": now,
            "exp": now + 600,
        }
        pem = self.signing_key.export_to_pem(private_key=True, password=None)
        return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": self.signing_key.key_id})

    def handle(self, request):
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={
                "issuer": f"https://{DOMAIN}/",
                "token_endpoint": f"https://{DOMAIN}/oauth/token",
                "jwks_uri": f"https://{DOMAIN}/.well-known/jwks.json",
            })
        if path == "/.well-known/jwks.json":
            return httpx.Response(200, json={"keys": [json.loads(self.signing_key.export_public())]})
        if path == "/oauth/token":
            self.token_requests.append(request)
            return self.token_responses.pop(0)
        return httpx.Response(404)


def mfa_required_response():
    return httpx.Response(403, json={
        "error": "mfa_required",
        "error_description": "Multifactor authentication required",
        "mfa_token": RAW_MFA_TOKEN,
    })


def tokens_response(mock):
    return httpx.Response(200, json={
        "access_token": "access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "refresh-token",
        "scope": SCOPE,
        "id_token": mock.id_token(),
    })


def request_with_cookies(response=None):
    jar = {}
    for header in response.headers.getlist("set-cookie") if response is not None else []:
        cookie = SimpleCookie(header)
        for name, morsel in cookie.items():
            if morsel["max-age"] == "0" or not morsel.value:
                jar.pop(name, None)
            else:
                jar[name] = morsel.value
    headers = [(b"cookie", "; ".join(f"{k}={v}" for k, v in jar.items()).encode())] if jar else []
    return Request({"type": "http", "headers": headers})


async def sign_in_requiring_mfa(auth_client, mock):
    mock.token_responses.append(mfa_required_response())
    response = Response()
    with pytest.raises(MfaRequiredError) as exc_info:
        await auth_client.signin_with_passkey(
            auth_session="sess_abc123",
            authn_response=PasskeyAuthResponse(
                id="cred_abc123",
                rawId="cred_abc123",
                type="public-key",
                response={"clientDataJSON": "client-data", "authenticatorData": "auth-data", "signature": "sig"},
            ),
            scope=SCOPE,
            audience=AUDIENCE,
            store_options={"request": request_with_cookies(), "response": response},
        )
    return exc_info.value, response


@pytest.fixture(scope="module")
def signing_key():
    return jwk.JWK.generate(kty="RSA", size=2048, kid="test-key")


@pytest.fixture
def auth_client():
    """Fixture providing an AuthClient with an audience configured."""
    return AuthClient(Auth0Config(
        domain=DOMAIN,
        client_id=CLIENT_ID,
        client_secret="test_client_secret",
        app_base_url="https://example.com",
        secret="test_secret_key_minimum_32_characters",
        audience=AUDIENCE,
    ))


@pytest.fixture
def auth0(auth_client, signing_key, monkeypatch):
    """Fixture routing the SDK's HTTP calls to a MockAuth0 once the client is built."""
    mock = MockAuth0(signing_key)
    real_client = httpx.AsyncClient

    class MockedAsyncClient(real_client):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(mock.handle)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", MockedAsyncClient)
    return mock


class TestPasskeyMfa:
    """Test passkey sign-in and MFA completion through the real ServerClient with a mocked Auth0."""

    @pytest.mark.asyncio
    async def test_signin_with_passkey_mfa_required_raises_with_encrypted_token(self, auth_client, auth0):
        """Test that an mfa_required response raises MfaRequiredError carrying a token other than the raw one."""
        error, _ = await sign_in_requiring_mfa(auth_client, auth0)

        assert error.mfa_token
        assert error.mfa_token != RAW_MFA_TOKEN

    @pytest.mark.asyncio
    async def test_signin_with_passkey_mfa_required_creates_no_session(self, auth_client, auth0):
        """Test that no user session exists after sign-in stops at the MFA requirement."""
        _, response = await sign_in_requiring_mfa(auth_client, auth0)

        user = await auth_client.client.get_user(
            store_options={"request": request_with_cookies(response), "response": Response()}
        )

        assert user is None

    @pytest.mark.asyncio
    async def test_mfa_verify_with_persist_creates_session(self, auth_client, auth0):
        """Test that mfa.verify with persist creates the session and get_access_token finds its token."""
        error, response = await sign_in_requiring_mfa(auth_client, auth0)
        auth0.token_responses.append(tokens_response(auth0))

        await auth_client.client.mfa.verify(
            {"mfa_token": error.mfa_token, "otp": "123456", "persist": True},
            store_options={"request": request_with_cookies(response), "response": response},
        )

        store_options = {"request": request_with_cookies(response), "response": Response()}
        user = await auth_client.client.get_user(store_options=store_options)
        access_token = await auth_client.client.get_access_token(store_options=store_options)
        assert user["sub"] == "auth0|abc123"
        assert access_token == "access-token"

    @pytest.mark.asyncio
    async def test_mfa_verify_sends_the_raw_token_and_the_code(self, auth_client, auth0):
        """Test that verify decrypts the token for Auth0 and sends the one-time password grant."""
        error, response = await sign_in_requiring_mfa(auth_client, auth0)
        auth0.token_responses.append(tokens_response(auth0))

        await auth_client.client.mfa.verify(
            {"mfa_token": error.mfa_token, "otp": "123456", "persist": True},
            store_options={"request": request_with_cookies(response), "response": response},
        )

        sent = parse_qs(auth0.token_requests[-1].content.decode())
        assert sent["grant_type"] == ["http://auth0.com/oauth/grant-type/mfa-otp"]
        assert sent["mfa_token"] == [RAW_MFA_TOKEN]
        assert sent["otp"] == ["123456"]

    @pytest.mark.asyncio
    async def test_mfa_verify_wrong_code_raises_and_creates_no_session(self, auth_client, auth0):
        """Test that a rejected code raises MfaVerifyError and leaves no session behind."""
        error, response = await sign_in_requiring_mfa(auth_client, auth0)
        auth0.token_responses.append(httpx.Response(403, json={
            "error": "invalid_grant",
            "error_description": "Wrong one-time password",
        }))
        verify_response = Response()

        with pytest.raises(MfaVerifyError):
            await auth_client.client.mfa.verify(
                {"mfa_token": error.mfa_token, "otp": "000000", "persist": True},
                store_options={"request": request_with_cookies(response), "response": verify_response},
            )

        user = await auth_client.client.get_user(
            store_options={"request": request_with_cookies(verify_response), "response": Response()}
        )
        assert user is None
