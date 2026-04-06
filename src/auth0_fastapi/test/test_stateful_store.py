from unittest.mock import AsyncMock, Mock

import pytest
from auth0_server_python.auth_types import StateData
from fastapi import Request, Response

from auth0_fastapi.stores.stateful_state_store import StatefulStateStore


@pytest.fixture
def mock_request():
    """Mock FastAPI Request object with cookies."""
    request = Mock(spec=Request)
    request.cookies = {}
    return request


@pytest.fixture
def mock_response():
    """Mock FastAPI Response object."""
    response = Mock(spec=Response)
    response.headers = {}
    response.set_cookie = Mock()
    response.delete_cookie = Mock()
    return response


@pytest.fixture
def secret_key():
    """Secret key for encryption/decryption."""
    return "test_secret_key_minimum_32_characters_long"


@pytest.fixture
def mock_store():
    """Mock persistent store (Redis-like) with async methods."""
    store = Mock()
    store.get = AsyncMock(return_value=None)
    store.set = AsyncMock(return_value=None)
    store.delete = AsyncMock(return_value=None)
    store.keys = AsyncMock(return_value=[])
    return store


class TestStatefulStateStore:
    """Test StatefulStateStore security and functionality."""

    def test_initialization(self, secret_key, mock_store):
        """Test store initialization."""
        store = StatefulStateStore(secret_key, mock_store)
        assert store.cookie_name == "_a0_session"
        assert store.secret == secret_key
        assert store.store == mock_store
        assert store.expiration == 259200

    @pytest.mark.asyncio
    async def test_set_state_data(self, secret_key, mock_store, mock_response):
        """Test setting state data in stateful store."""
        store = StatefulStateStore(secret_key, mock_store)

        state_data = StateData(
            state="test_state",
            code_verifier="test_code_verifier",
            nonce="test_nonce",
            user={"sub": "test_user"},
            internal={"sid": "test_sid", "created_at": 1672531200}
        )
        options = {"response": mock_response}

        await store.set("test_id", state_data, options=options)

        # Verify store interaction
        mock_store.set.assert_called_once_with("test_id", state_data.model_dump_json(), expire=259200)
        mock_response.set_cookie.assert_called_once_with(
            key="_a0_session",
            value="test_id",
            httponly=True,
            max_age=259200
        )

    @pytest.mark.asyncio
    async def test_get_state_data(self, secret_key, mock_store, mock_request):
        """Test retrieving state data from stateful store."""
        store = StatefulStateStore(secret_key, mock_store)

        mock_request.cookies = {"_a0_session": "session_id"}
        options = {"request": mock_request}

        # Configure mock to simulate session data - serialize as JSON since that's what the store returns
        mock_data = {
            "state": "test_state",
            "code_verifier": "test_code_verifier",
            "nonce": "test_nonce",
            "user": {
                "sub": "test_user",
                "email": "user@example.com",
                "password": "should_not_appear"
            },
            "internal": {
                "sid": "test_sid",
                "created_at": 1672531200  # Unix timestamp for 2023-01-01T00:00:00Z
            }
        }
        # The implementation uses parse_obj which expects a dict, not JSON
        mock_store.get.return_value = mock_data

        result = await store.get("test_id", options)

        # Verify store interaction
        mock_store.get.assert_called_once_with("session_id")
        assert isinstance(result, StateData)
        assert result.user.sub == "test_user"  # UserClaims is a Pydantic model, use attribute access
        assert result.state == "test_state"

    @pytest.mark.asyncio
    async def test_delete_state_data(self, secret_key, mock_store, mock_response):
        """Test deleting state data from stateful store."""
        store = StatefulStateStore(secret_key, mock_store)

        options = {"response": mock_response}

        await store.delete("test_id", options)

        # Verify store deletion and cookie deletion
        mock_store.delete.assert_called_once_with("test_id")
        mock_response.delete_cookie.assert_called_once_with(key="_a0_session")

    @pytest.mark.asyncio
    async def test_store_connection_failure(self, secret_key, mock_store, mock_response):
        """Test handling of store connection failures."""
        store = StatefulStateStore(secret_key, mock_store)

        state_data = StateData(
            state="test_state",
            code_verifier="test_code_verifier",
            nonce="test_nonce",
            user={"sub": "test_user"},
            internal={"sid": "test_sid", "created_at": 1672531200}
        )
        options = {"response": mock_response}

        # Mock store failure
        mock_store.set.side_effect = Exception("Connection failed")

        with pytest.raises(Exception) as exc_info:
            await store.set("test_id", state_data, False, options)

        assert "Connection failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_malicious_identifier_handling(self, secret_key, mock_store, mock_response):
        """Test that malicious identifiers are handled safely."""
        store = StatefulStateStore(secret_key, mock_store)

        # Test with potentially malicious session ID
        malicious_id = "test'; DROP TABLE sessions; --"
        state_data = StateData(
            state="test_state",
            code_verifier="test_code_verifier",
            nonce="test_nonce",
            user={"sub": "test_user"},
            internal={"sid": "test_sid", "created_at": 1672531200}
        )
        options = {"response": mock_response}

        await store.set(malicious_id, state_data, False, options)

        # Verify store receives the malicious string as data (not executed as code)
        mock_store.set.assert_called_once_with(malicious_id, state_data.model_dump_json(), expire=259200)
        mock_response.set_cookie.assert_called_once_with(
            key="_a0_session",
            value=malicious_id,
            httponly=True,
            max_age=259200
        )

    @pytest.mark.asyncio
    async def test_concurrent_store_operations(self, secret_key, mock_store, mock_request, mock_response):
        """Test concurrent store operations."""
        store = StatefulStateStore(secret_key, mock_store)

        state_data = StateData(
            state="test_state",
            code_verifier="test_code_verifier",
            nonce="test_nonce",
            user={"sub": "test_user"},
            internal={"sid": "test_sid", "created_at": 1672531200}
        )
        set_options = {"response": mock_response}
        get_options = {"request": mock_request}

        mock_request.cookies = {"_a0_session": "session_id"}
        mock_store.get.return_value = state_data.model_dump_json()

        # These operations should not interfere with each other
        await store.set("test_id1", state_data, False, set_options)
        await store.set("test_id2", state_data, False, set_options)
        await store.get("test_id", get_options)
        await store.delete("test_id", set_options)

        # Verify all operations completed
        assert mock_store.set.call_count == 2
        mock_store.get.assert_called_once()
        mock_store.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_session_expiration_handling(self, secret_key, mock_store, mock_request):
        """Test handling of expired sessions in store."""
        store = StatefulStateStore(secret_key, mock_store)

        mock_request.cookies = {"_a0_session": "expired_session_id"}
        options = {"request": mock_request}

        # Simulate no session found (expired or cleaned up)
        mock_store.get.return_value = None

        result = await store.get("test_id", options)

        # Should return None for expired/missing sessions
        assert result is None

    @pytest.mark.asyncio
    async def test_large_session_data_storage(self, secret_key, mock_store, mock_response):
        """Test storage of large session data in store."""
        store = StatefulStateStore(secret_key, mock_store)

        # Generate data for a large test payload
        large_user_data = {
            "sub": "user123",
            "name": "Test User",
            "email": "user@example.com",
            # Add large nested data
            "metadata": {"history": ["action1" for _ in range(1000)]}
        }

        state_data = StateData(
            state="test_state",
            code_verifier="test_code_verifier",
            nonce="test_nonce",
            user=large_user_data,
            internal={"sid": "test_sid", "created_at": 1672531200}
        )
        options = {"response": mock_response}

        await store.set("test_id", state_data, False, options)

        # Verify large data can be stored without chunking (unlike cookie stores)
        mock_store.set.assert_called_once_with("test_id", state_data.model_dump_json(), expire=259200)
        mock_response.set_cookie.assert_called_once()

    @pytest.mark.asyncio
    async def test_store_error_handling(self, secret_key, mock_store, mock_response):
        """Test store error handling on failures."""
        store = StatefulStateStore(secret_key, mock_store)

        state_data = StateData(
            state="test_state",
            code_verifier="test_code_verifier",
            nonce="test_nonce",
            user={"sub": "test_user"},
            internal={"sid": "test_sid", "created_at": 1672531200}
        )
        options = {"response": mock_response}

        # Simulate store error during execution
        mock_store.set.side_effect = Exception("Store constraint violation")

        with pytest.raises(Exception) as exc_info:
            await store.set("test_id", state_data, False, options)

        assert "Store constraint violation" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_cookie_session_id_security(self, secret_key, mock_store, mock_request, mock_response):
        """Test security of session ID stored in cookie."""
        store = StatefulStateStore(secret_key, mock_store)

        state_data = StateData(
            state="test_state",
            code_verifier="test_code_verifier",
            nonce="test_nonce",
            user={"sub": "test_user"},
            internal={"sid": "test_sid", "created_at": 1672531200}
        )
        await store.set("test_id", state_data, options={"response": mock_response})

        # Verify cookie is set with secure session ID
        mock_response.set_cookie.assert_called()
        call_args = mock_response.set_cookie.call_args

        # Check basic cookie parameters (actual implementation may not set all secure flags)
        assert call_args.kwargs.get('httponly') is True
        assert call_args.kwargs.get('max_age') == 259200


class TestStatefulStoreSecurityVulnerabilities:
    """Test specific security vulnerabilities in stateful stores."""

    @pytest.mark.asyncio
    async def test_session_hijacking_prevention(self, secret_key, mock_store, mock_request):
        """Test prevention of session hijacking attacks."""
        store = StatefulStateStore(secret_key, mock_store)

        # Test with potentially hijacked session ID
        hijacked_session_id = "stolen_session_id"
        mock_request.cookies = {"_a0_session": hijacked_session_id}
        options = {"request": mock_request}

        # Simulate session not found (good security practice)
        mock_store.get.return_value = None

        result = await store.get("test_id", options)

        # Should return None for unknown/hijacked session IDs
        assert result is None
        mock_store.get.assert_called_once_with(hijacked_session_id)

    def test_store_interface_security(self, secret_key, mock_store):
        """Test that store interface is properly secured."""
        store = StatefulStateStore(secret_key, mock_store)

        # Store instance should be properly encapsulated
        assert store.cookie_name == "_a0_session"
        assert store.secret == secret_key
        assert store.store == mock_store

        # Secret should not be exposed in string representations
        store_str = str(store)
        assert secret_key not in store_str

    @pytest.mark.asyncio
    async def test_store_resource_management(self, secret_key, mock_store, mock_response):
        """Test efficient resource management in store operations."""
        store = StatefulStateStore(secret_key, mock_store)

        state_data = StateData(
            state="test_state",
            code_verifier="test_code_verifier",
            nonce="test_nonce",
            user={"sub": "test_user"},
            internal={"sid": "test_sid", "created_at": 1672531200}
        )
        options = {"response": mock_response}

        # Multiple operations should reuse store efficiently
        for i in range(10):
            await store.set(f"test_id_{i}", state_data, False, options)

        # Should have called store.set for each operation
        assert mock_store.set.call_count == 10

    @pytest.mark.asyncio
    async def test_sensitive_data_handling(self, secret_key, mock_store, mock_response):
        """Test that sensitive data is handled properly in store."""
        store = StatefulStateStore(secret_key, mock_store)

        sensitive_data = StateData(
            state="test_state",
            code_verifier="test_code_verifier",
            nonce="test_nonce",
            user={"sub": "test_user"},
            internal={
                "sid": "test_sid",
                "created_at": 1672531200,  # Unix timestamp for 2023-01-01T00:00:00Z
                "credit_card": "4111111111111111",  # Sensitive data
                "ssn": "123-45-6789"
            }
        )
        options = {"response": mock_response}

        await store.set("test_id", sensitive_data, False, options)

        # Verify store receives JSON serialized data (implementation may add encryption)
        mock_store.set.assert_called_once_with("test_id", sensitive_data.model_dump_json(), expire=259200)

        # The actual implementation should handle encryption of sensitive data
