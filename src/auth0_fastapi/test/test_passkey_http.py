import json
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from auth0_server_python.auth_types import PasskeyAuthResponse, PasskeyUserProfile
from auth0_server_python.error import (
    MfaRequiredError,
    MfaVerifyError,
    OrganizationTokenValidationError,
    PasskeyError,
)
from fastapi import Request, Response
from jwcrypto import jwk

from auth0_fastapi.auth.auth_client import AuthClient
from auth0_fastapi.config import Auth0Config

DOMAIN = "test.auth0.com"
CLIENT_ID = "test_client_id"
AUDIENCE = "https://api.example.com"
CONNECTION = "Username-Password-Authentication"
RAW_MFA_TOKEN = "raw-mfa-token-issued-by-auth0"
SCOPE = "openid profile email offline_access"
PUBLIC_KEY = {"challenge": "Y2hhbGxlbmdl", "rpId": DOMAIN, "timeout": 60000}


class MockAuth0:
    """Answers the Auth0 endpoints the passkey challenges, sign-in and MFA verification call."""

    def __init__(self, signing_key):
        self.signing_key = signing_key
        self.challenge_responses = []
        self.challenge_requests = []
        self.token_responses = []
        self.token_requests = []

    def id_token(self, **extra_claims):
        now = int(time.time())
        claims = {
            "iss": f"https://{DOMAIN}/",
            "aud": CLIENT_ID,
            "sub": "auth0|abc123",
            "iat": now,
            "exp": now + 600,
            **extra_claims,
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
        if path in ("/passkey/register", "/passkey/challenge"):
            self.challenge_requests.append(request)
            return self.challenge_responses.pop(0)
        if path == "/oauth/token":
            self.token_requests.append(request)
            return self.token_responses.pop(0)
        return httpx.Response(404)


def challenge_response(**extra):
    return httpx.Response(200, json={
        "auth_session": "sess_abc123",
        "authn_params_public_key": PUBLIC_KEY,
        **extra,
    })


def mfa_required_response():
    return httpx.Response(403, json={
        "error": "mfa_required",
        "error_description": "Multifactor authentication required",
        "mfa_token": RAW_MFA_TOKEN,
    })


def tokens_response(mock, token_type="Bearer", **claims):
    return httpx.Response(200, json={
        "access_token": "access-token",
        "token_type": token_type,
        "expires_in": 3600,
        "refresh_token": "refresh-token",
        "scope": SCOPE,
        "id_token": mock.id_token(**claims),
    })


def authn_response():
    return PasskeyAuthResponse(
        id="cred_abc123",
        rawId="cred_abc123",
        type="public-key",
        response={"clientDataJSON": "client-data", "authenticatorData": "auth-data", "signature": "sig"},
    )


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


def store_options(response=None):
    return {"request": request_with_cookies(response), "response": Response()}


async def sign_in_requiring_mfa(auth_client, mock):
    mock.token_responses.append(mfa_required_response())
    response = Response()
    with pytest.raises(MfaRequiredError) as exc_info:
        await auth_client.signin_with_passkey(
            auth_session="sess_abc123",
            authn_response=authn_response(),
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


class TestPasskeyHttp:
    """Test the requests the real ServerClient sends to a mocked Auth0 for the passkey methods."""

    @pytest.mark.asyncio
    async def test_passkey_signup_challenge_sends_profile_connection_and_client_ip(self, auth_client, auth0):
        """Test that the signup challenge body and forwarded-for header carry every argument."""
        auth0.challenge_responses.append(challenge_response(verification_required=["email", "phone"]))

        result = await auth_client.passkey_signup_challenge(
            user_profile=PasskeyUserProfile(email="new.user@example.com", phone_number="+15551234567"),
            connection=CONNECTION,
            organization="org_abc123",
            delivery_method="voice",
            client_ip="203.0.113.7",
            store_options=store_options(),
        )

        request = auth0.challenge_requests[-1]
        sent = json.loads(request.content)
        assert result.verification_required == ["email", "phone"]
        assert request.headers["auth0-forwarded-for"] == "203.0.113.7"
        assert sent["user_profile"] == {"email": "new.user@example.com", "phone_number": "+15551234567"}
        assert sent["realm"] == CONNECTION
        assert sent["organization"] == "org_abc123"
        assert sent["delivery_method"] == "voice"

    @pytest.mark.asyncio
    async def test_passkey_login_challenge_sends_connection_and_client_ip_without_username(self, auth_client, auth0):
        """Test that the login challenge forwards the IP and connection and never sends a username."""
        auth0.challenge_responses.append(challenge_response())

        await auth_client.passkey_login_challenge(
            connection=CONNECTION,
            organization="org_abc123",
            client_ip="203.0.113.7",
            store_options=store_options(),
        )

        request = auth0.challenge_requests[-1]
        sent = json.loads(request.content)
        assert request.headers["auth0-forwarded-for"] == "203.0.113.7"
        assert sent["realm"] == CONNECTION
        assert sent["organization"] == "org_abc123"
        assert "username" not in sent

    @pytest.mark.asyncio
    async def test_passkey_challenge_without_client_ip_sends_no_forwarded_for_header(self, auth_client, auth0):
        """Test that the forwarded-for header is left out when client_ip is not given."""
        auth0.challenge_responses.append(challenge_response())

        await auth_client.passkey_login_challenge(store_options=store_options())

        assert "auth0-forwarded-for" not in auth0.challenge_requests[-1].headers

    @pytest.mark.asyncio
    async def test_passkey_signup_challenge_rate_limit_raises_with_status_and_retry_after(self, auth_client, auth0):
        """Test that a 429 on the challenge surfaces status_code and retry_after on PasskeyError."""
        auth0.challenge_responses.append(httpx.Response(429, text="Too Many Requests", headers={"Retry-After": "7"}))

        with pytest.raises(PasskeyError) as exc_info:
            await auth_client.passkey_signup_challenge(
                user_profile=PasskeyUserProfile(email="new.user@example.com"),
                store_options=store_options(),
            )

        assert exc_info.value.status_code == 429
        assert exc_info.value.retry_after == 7

    @pytest.mark.asyncio
    async def test_signin_with_passkey_sends_codes_scope_audience_and_client_ip(self, auth_client, auth0):
        """Test that the token request carries the verification codes, scope, audience and forwarded-for."""
        auth0.token_responses.append(tokens_response(auth0))

        await auth_client.signin_with_passkey(
            auth_session="sess_abc123",
            authn_response=authn_response(),
            verification={"email": "123456", "phone": "654321"},
            connection=CONNECTION,
            scope=SCOPE,
            audience=AUDIENCE,
            client_ip="203.0.113.7",
            store_options=store_options(),
        )

        request = auth0.token_requests[-1]
        sent = json.loads(request.content)
        assert request.headers["auth0-forwarded-for"] == "203.0.113.7"
        assert sent["auth_session"] == "sess_abc123"
        assert sent["verification"] == {"email": "123456", "phone": "654321"}
        assert sent["realm"] == CONNECTION
        assert sent["scope"] == SCOPE
        assert sent["audience"] == AUDIENCE

    @pytest.mark.asyncio
    async def test_signin_with_passkey_success_stores_the_session(self, auth_client, auth0):
        """Test that a successful sign-in stores a session whose user and token can be read back."""
        auth0.token_responses.append(tokens_response(auth0))
        response = Response()

        await auth_client.signin_with_passkey(
            auth_session="sess_abc123",
            authn_response=authn_response(),
            scope=SCOPE,
            audience=AUDIENCE,
            store_options={"request": request_with_cookies(), "response": response},
        )

        user = await auth_client.client.get_user(store_options=store_options(response))
        access_token = await auth_client.client.get_access_token(store_options=store_options(response))
        assert user["sub"] == "auth0|abc123"
        assert access_token == "access-token"

    @pytest.mark.asyncio
    async def test_signin_with_passkey_rate_limit_raises_with_status_and_retry_after(self, auth_client, auth0):
        """Test that a 429 on the token request surfaces status_code and retry_after on PasskeyError."""
        auth0.token_responses.append(httpx.Response(429, text="Too Many Requests", headers={"Retry-After": "7"}))

        with pytest.raises(PasskeyError) as exc_info:
            await auth_client.signin_with_passkey(
                auth_session="sess_abc123",
                authn_response=authn_response(),
                store_options=store_options(),
            )

        assert exc_info.value.status_code == 429
        assert exc_info.value.retry_after == 7

    @pytest.mark.asyncio
    async def test_signin_with_passkey_wrong_code_is_retryable_with_the_new_session(self, auth_client, auth0):
        """Test that a wrong code keeps the session alive and exposes what is still unverified."""
        auth0.token_responses.append(httpx.Response(400, json={
            "error": "invalid_grant",
            "error_description": "Wrong code",
            "auth_session": "sess_new",
            "verification_required": ["email"],
        }))

        with pytest.raises(PasskeyError) as exc_info:
            await auth_client.signin_with_passkey(
                auth_session="sess_abc123",
                authn_response=authn_response(),
                verification={"email": "000000"},
                store_options=store_options(),
            )

        assert exc_info.value.is_verification_retryable is True
        assert exc_info.value.auth_session == "sess_new"
        assert exc_info.value.verification_required == ["email"]

    @pytest.mark.asyncio
    async def test_signin_with_passkey_expired_session_is_not_retryable(self, auth_client, auth0):
        """Test that invalid_grant without an auth_session is terminal."""
        auth0.token_responses.append(httpx.Response(400, json={
            "error": "invalid_grant",
            "error_description": "Session expired",
        }))

        with pytest.raises(PasskeyError) as exc_info:
            await auth_client.signin_with_passkey(
                auth_session="sess_abc123",
                authn_response=authn_response(),
                store_options=store_options(),
            )

        assert exc_info.value.is_verification_retryable is False

    @pytest.mark.asyncio
    async def test_signin_with_passkey_organization_claim_mismatch_raises(self, auth_client, auth0):
        """Test that a requested organization fails closed when the ID token carries another one."""
        auth0.token_responses.append(tokens_response(auth0, org_id="org_other"))

        with pytest.raises(OrganizationTokenValidationError):
            await auth_client.signin_with_passkey(
                auth_session="sess_abc123",
                authn_response=authn_response(),
                organization="org_abc123",
                store_options=store_options(),
            )

    @pytest.mark.asyncio
    async def test_signin_with_passkey_organization_claim_match_succeeds(self, auth_client, auth0):
        """Test that the requested organization is sent and accepted when the ID token matches."""
        auth0.token_responses.append(tokens_response(auth0, org_id="org_abc123"))

        await auth_client.signin_with_passkey(
            auth_session="sess_abc123",
            authn_response=authn_response(),
            organization="org_abc123",
            store_options=store_options(),
        )

        assert json.loads(auth0.token_requests[-1].content)["organization"] == "org_abc123"

    @pytest.mark.asyncio
    async def test_signin_with_passkey_dpop_key_sends_a_proof_and_rejects_a_bearer_token(self, auth_client, auth0):
        """Test that dpop_key adds the DPoP header and a non-DPoP token response is refused."""
        dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")
        auth0.token_responses.append(tokens_response(auth0, token_type="Bearer"))

        with pytest.raises(PasskeyError):
            await auth_client.signin_with_passkey(
                auth_session="sess_abc123",
                authn_response=authn_response(),
                dpop_key=dpop_key,
                store_options=store_options(),
            )

        assert "dpop" in auth0.token_requests[-1].headers


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

        user = await auth_client.client.get_user(store_options=store_options(response))

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

        user = await auth_client.client.get_user(store_options=store_options(response))
        access_token = await auth_client.client.get_access_token(store_options=store_options(response))
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

        user = await auth_client.client.get_user(store_options=store_options(verify_response))
        assert user is None
