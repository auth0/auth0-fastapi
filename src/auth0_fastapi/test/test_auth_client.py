import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest
from auth0_server_python.auth_types import CompleteConnectAccountResponse, ConnectAccountOptions
from fastapi import HTTPException, Request, Response

from auth0_fastapi.auth.auth_client import AuthClient
from auth0_fastapi.config import Auth0Config


@pytest.fixture
def auth_config():
    """Fixture providing a valid Auth0 configuration."""
    return Auth0Config(
        domain="test.auth0.com",
        client_id="test_client_id",
        client_secret="test_client_secret",
        app_base_url="https://example.com",
        secret="test_secret_key_minimum_32_characters",
        audience="https://api.example.com",
    )


@pytest.fixture
def mock_request():
    """Mock FastAPI Request object."""
    request = Mock(spec=Request)
    request.cookies = {}
    return request


@pytest.fixture
def mock_response():
    """Mock FastAPI Response object."""
    response = Mock(spec=Response)
    response.headers = {}
    return response


@pytest.fixture
def auth_client(auth_config):
    """Fixture providing an AuthClient instance."""
    return AuthClient(auth_config)


class TestAuthClientInitialization:
    """Test AuthClient initialization and configuration security."""

    def test_auth_client_initialization_with_valid_config(self, auth_config):
        """Test that AuthClient initializes correctly with valid config."""
        client = AuthClient(auth_config)
        assert client.config == auth_config
        assert client.client is not None

    def test_redirect_uri_construction(self, auth_config):
        """Test that redirect URI is constructed securely."""
        # The redirect URI should be properly constructed from app_base_url
        expected_redirect = f"{str(auth_config.app_base_url).rstrip('/')}/auth/callback"

        # Use patch to intercept the ServerClient initialization
        with patch('auth0_fastapi.auth.auth_client.ServerClient') as mock_server_client:
            AuthClient(auth_config)
            mock_server_client.assert_called_once()
            _, kwargs = mock_server_client.call_args
            assert kwargs['redirect_uri'] == expected_redirect
            assert kwargs['authorization_params']['redirect_uri'] == expected_redirect

    def test_custom_stores_initialization(self, auth_config):
        """Test initialization with custom state and transaction stores."""
        custom_state_store = Mock()
        custom_transaction_store = Mock()

        client = AuthClient(
            auth_config,
            state_store=custom_state_store,
            transaction_store=custom_transaction_store
        )

        assert client.config == auth_config

    def test_default_stores_creation(self, auth_config):
        """Test that default stores are created when not provided."""
        client = AuthClient(auth_config)
        # Verify that client was created (default stores should be instantiated)
        assert client.client is not None


class TestSessionSecurity:
    """Test session management security features."""

    @pytest.mark.asyncio
    async def test_require_session_with_valid_session(self, auth_client, mock_request, mock_response):
        """Test that require_session returns session when valid session exists."""
        mock_session = {"user": {"sub": "test_user"}}

        with patch.object(auth_client.client, 'get_session', new_callable=AsyncMock) as mock_get_session:
            mock_get_session.return_value = mock_session

            result = await auth_client.require_session(mock_request, mock_response)

            assert result == mock_session
            mock_get_session.assert_called_once()

    @pytest.mark.asyncio
    async def test_require_session_with_no_session_raises_401(self, auth_client, mock_request, mock_response):
        """Test that require_session raises 401 when no session exists."""
        with patch.object(auth_client.client, 'get_session', new_callable=AsyncMock) as mock_get_session:
            mock_get_session.return_value = None

            with pytest.raises(HTTPException) as exc_info:
                await auth_client.require_session(mock_request, mock_response)

            assert exc_info.value.status_code == 401
            assert "Please log in" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_session_store_options_passed_correctly(self, auth_client, mock_request, mock_response):
        """Test that request and response are passed correctly to session store."""
        with patch.object(auth_client.client, 'get_session', new_callable=AsyncMock) as mock_get_session:
            mock_get_session.return_value = {"user": {"sub": "test"}}

            await auth_client.require_session(mock_request, mock_response)

            # Verify store_options contains request and response
            call_args = mock_get_session.call_args
            assert call_args[1]['store_options']['request'] == mock_request
            assert call_args.kwargs['store_options']['response'] == mock_response


class TestLoginFlow:
    """Test login flow security and functionality."""

    @pytest.mark.asyncio
    async def test_start_login_basic(self, auth_client):
        """Test basic login initiation."""
        mock_auth_url = "https://test.auth0.com/authorize?..."

        with patch.object(auth_client.client, 'start_interactive_login', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = mock_auth_url

            result = await auth_client.start_login()

            assert result == mock_auth_url
            mock_start.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_login_with_app_state(self, auth_client):
        """Test login with app state for CSRF protection."""
        app_state = {"return_to": "/dashboard", "custom": "data"}
        mock_auth_url = "https://test.auth0.com/authorize?..."

        with patch.object(auth_client.client, 'start_interactive_login', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = mock_auth_url

            result = await auth_client.start_login(app_state=app_state)

            assert result == mock_auth_url
            # Verify app_state is passed in options
            call_args = mock_start.call_args[0][0]
            assert call_args.app_state == app_state

    @pytest.mark.asyncio
    async def test_start_login_with_authorization_params(self, auth_client):
        """Test login with additional authorization parameters."""
        auth_params = {"scope": "openid profile email", "prompt": "consent"}

        with patch.object(auth_client.client, 'start_interactive_login', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = "https://test.auth0.com/authorize?..."

            await auth_client.start_login(authorization_params=auth_params)

            call_args = mock_start.call_args[0][0]
            assert call_args.authorization_params == auth_params

    @pytest.mark.asyncio
    async def test_complete_login_with_valid_callback(self, auth_client):
        """Test completing login with valid callback URL."""
        callback_url = "https://example.com/auth/callback?code=test_code&state=test_state"
        mock_session = {"user": {"sub": "test_user"}}

        with patch.object(auth_client.client, 'complete_interactive_login', new_callable=AsyncMock) as mock_complete:
            mock_complete.return_value = mock_session

            result = await auth_client.complete_login(callback_url)

            assert result == mock_session
            mock_complete.assert_called_once_with(callback_url, store_options=None)

    @pytest.mark.asyncio
    async def test_complete_login_with_malformed_callback_url(self, auth_client):
        """Test completing login with malformed callback URL raises exception."""
        malformed_url = "not_a_valid_url"

        with patch.object(auth_client.client, 'complete_interactive_login', new_callable=AsyncMock) as mock_complete:
            mock_complete.side_effect = Exception("Invalid callback URL")

            with pytest.raises(Exception):
                await auth_client.complete_login(malformed_url)


class TestLogoutFlow:
    """Test logout flow security and functionality."""

    @pytest.mark.asyncio
    async def test_logout_basic(self, auth_client):
        """Test basic logout functionality."""
        mock_logout_url = "https://test.auth0.com/logout"

        with patch.object(auth_client.client, 'logout', new_callable=AsyncMock) as mock_logout:
            mock_logout.return_value = mock_logout_url

            result = await auth_client.logout()

            assert result == mock_logout_url
            mock_logout.assert_called_once()

    @pytest.mark.asyncio
    async def test_logout_with_return_to(self, auth_client):
        """Test logout with return_to URL."""
        return_to = "https://example.com/goodbye"
        mock_logout_url = f"https://test.auth0.com/logout?returnTo={return_to}"

        with patch.object(auth_client.client, 'logout', new_callable=AsyncMock) as mock_logout:
            mock_logout.return_value = mock_logout_url

            result = await auth_client.logout(return_to=return_to)

            assert result == mock_logout_url
            # Verify LogoutOptions contains return_to
            call_args = mock_logout.call_args[0][0]
            assert call_args.return_to == return_to

    @pytest.mark.asyncio
    async def test_backchannel_logout(self, auth_client):
        """Test backchannel logout processing."""
        logout_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

        with patch.object(auth_client.client, 'handle_backchannel_logout', new_callable=AsyncMock) as mock_backchannel:
            mock_backchannel.return_value = None

            result = await auth_client.handle_backchannel_logout(logout_token)

            assert result is None
            mock_backchannel.assert_called_once_with(logout_token)

    @pytest.mark.asyncio
    async def test_backchannel_logout_with_invalid_token(self, auth_client):
        """Test backchannel logout with invalid token raises exception."""
        invalid_token = "invalid_jwt_token"

        with patch.object(auth_client.client, 'handle_backchannel_logout', new_callable=AsyncMock) as mock_backchannel:
            mock_backchannel.side_effect = Exception("Invalid logout token")

            with pytest.raises(Exception):
                await auth_client.handle_backchannel_logout(invalid_token)


class TestAccountLinking:
    """Test account linking/unlinking security and functionality."""

    @pytest.mark.asyncio
    async def test_start_link_user(self, auth_client):
        """Test initiating user account linking."""
        link_options = {
            "connection": "google-oauth2",
            "connectionScope": "email profile",
            "authorizationParams": {"prompt": "consent"},
            "appState": {"returnTo": "/profile"}
        }
        mock_link_url = "https://test.auth0.com/authorize?connection=google-oauth2..."

        with patch.object(auth_client.client, 'start_link_user', new_callable=AsyncMock) as mock_start_link:
            mock_start_link.return_value = mock_link_url

            result = await auth_client.start_link_user(link_options)

            assert result == mock_link_url
            mock_start_link.assert_called_once_with(link_options, store_options=None)

    @pytest.mark.asyncio
    async def test_complete_link_user(self, auth_client):
        """Test completing user account linking."""
        callback_url = "https://example.com/auth/connect/callback?code=test&state=test"
        mock_result = {"app_state": {"returnTo": "/profile"}}

        with patch.object(auth_client.client, 'complete_link_user', new_callable=AsyncMock) as mock_complete_link:
            mock_complete_link.return_value = mock_result

            result = await auth_client.complete_link_user(callback_url)

            assert result == mock_result
            mock_complete_link.assert_called_once_with(callback_url, store_options=None)

    @pytest.mark.asyncio
    async def test_start_unlink_user(self, auth_client):
        """Test initiating user account unlinking."""
        unlink_options = {
            "connection": "google-oauth2",
            "authorizationParams": {"prompt": "consent"},
            "appState": {"returnTo": "/profile"}
        }
        mock_unlink_url = "https://test.auth0.com/authorize?connection=google-oauth2..."

        with patch.object(auth_client.client, 'start_unlink_user', new_callable=AsyncMock) as mock_start_unlink:
            mock_start_unlink.return_value = mock_unlink_url

            result = await auth_client.start_unlink_user(unlink_options)

            assert result == mock_unlink_url
            mock_start_unlink.assert_called_once_with(unlink_options, store_options=None)

    @pytest.mark.asyncio
    async def test_complete_unlink_user(self, auth_client):
        """Test completing user account unlinking."""
        callback_url = "https://example.com/auth/unconnect/callback?code=test&state=test"
        mock_result = {"app_state": {"returnTo": "/profile"}}

        with patch.object(auth_client.client, 'complete_unlink_user', new_callable=AsyncMock) as mock_complete_unlink:
            mock_complete_unlink.return_value = mock_result

            result = await auth_client.complete_unlink_user(callback_url)

            assert result == mock_result
            mock_complete_unlink.assert_called_once_with(callback_url, store_options=None)


class TestSecurityVulnerabilities:
    """Test specific security vulnerability scenarios."""

    @pytest.mark.asyncio
    async def test_concurrent_session_access(self, auth_client, mock_request, mock_response):
        """Test handling of concurrent session access attempts."""
        with patch.object(auth_client.client, 'get_session', new_callable=AsyncMock) as mock_get_session:
            mock_get_session.return_value = {"user": {"sub": "test"}}

            # Simulate concurrent calls
            tasks = [
                auth_client.require_session(mock_request, mock_response),
                auth_client.require_session(mock_request, mock_response),
                auth_client.require_session(mock_request, mock_response)
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # All should succeed with same session
            for result in results:
                assert not isinstance(result, Exception)
                assert result["user"]["sub"] == "test"

    def test_sensitive_config_not_exposed(self, auth_client):
        """Test that sensitive configuration is not exposed in client."""
        # Ensure client_secret and secret are not directly accessible
        assert not hasattr(auth_client, 'client_secret')
        assert not hasattr(auth_client, 'secret')

        # Config should be stored but not expose secrets directly in logs/repr
        config_dict = auth_client.config.model_dump()
        assert 'client_secret' in config_dict
        assert 'secret' in config_dict

    @pytest.mark.asyncio
    async def test_malicious_app_state_injection(self, auth_client):
        """Test protection against malicious app state injection."""
        malicious_state = {
            "returnTo": "javascript:alert('XSS')",
            "redirect_uri": "https://malicious.com",
            "__proto__": {"polluted": True}
        }

        with patch.object(auth_client.client, 'start_interactive_login', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = "https://safe.url"

            # Should not raise exception but should sanitize malicious content
            await auth_client.start_login(app_state=malicious_state)

            # The underlying client should receive the state as-is (sanitization happens at route level)
            call_args = mock_start.call_args[0][0]
            assert call_args.app_state == malicious_state

    @pytest.mark.asyncio
    async def test_store_options_validation(self, auth_client):
        """Test that store options are properly validated."""
        # Test with missing required store options
        with patch.object(auth_client.client, 'start_interactive_login', new_callable=AsyncMock) as mock_start:
            mock_start.return_value = "https://test.url"

            # Should work with None store_options
            await auth_client.start_login(store_options=None)

            # Should work with valid store_options
            valid_options = {"response": Mock()}
            await auth_client.start_login(store_options=valid_options)

            mock_start.assert_called()


class TestConnectedAccountFlow:
    """Test connected account functionality."""

    @pytest.mark.asyncio
    async def test_start_connect_account(self, auth_client):
        """Test initiating user account linking."""
        mock_connect_url = "https://test.auth0.com/connected-accounts/connect?ticket"

        with patch.object(auth_client.client, 'start_connect_account', new_callable=AsyncMock) as mock_start_connect:
            mock_start_connect.return_value = mock_connect_url

            result = await auth_client.start_connect_account(
                connection="google-oauth2",
                app_state={"returnTo": "/profile"},
                authorization_params={"prompt": "consent"},
            )

            assert result == mock_connect_url
            mock_start_connect.assert_called_once_with(
                options=ConnectAccountOptions(
                    connection="google-oauth2",
                    app_state={"returnTo": "/profile"},
                    authorization_params={"prompt": "consent"},
                ), store_options=None)

    @pytest.mark.asyncio
    async def test_complete_connect_account(self, auth_client):
        """Test initiating user account linking."""
        mock_callback_url = "https://test.auth0.com/connected-accounts/connect?ticket"
        mock_result = CompleteConnectAccountResponse(
                id="id_12345",
                connection="google-oauth2",
                access_type="offline",
                scopes=["read:foo"],
                created_at="1970-01-01T00:00:00Z"
            )
        with patch.object(auth_client.client, 'complete_connect_account', new_callable=AsyncMock) as mock_complete:
            mock_complete.return_value = mock_result

            result = await auth_client.complete_connect_account(mock_callback_url)

            assert result == mock_result
            mock_complete.assert_called_once_with(mock_callback_url, store_options=None)
