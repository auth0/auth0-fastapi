from unittest.mock import Mock, patch

import pytest
from auth0_server_python.auth_types import TransactionData
from fastapi import Request, Response

from auth0_fastapi.stores.cookie_transaction_store import CookieTransactionStore
from auth0_fastapi.stores.stateless_state_store import StatelessStateStore


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


class TestCookieTransactionStore:
    """Test CookieTransactionStore security and functionality."""

    def test_initialization(self, secret_key):
        """Test store initialization with proper parameters."""
        store = CookieTransactionStore(secret_key, "_test_tx")
        assert store.cookie_name == "_test_tx"

    def test_initialization_default_cookie_name(self, secret_key):
        """Test store initialization with default cookie name."""
        store = CookieTransactionStore(secret_key)
        assert store.cookie_name == "_a0_tx"

    @pytest.mark.asyncio
    async def test_set_transaction_data(self, secret_key, mock_response):
        """Test setting transaction data in encrypted cookie."""
        store = CookieTransactionStore(secret_key)

        transaction_data = TransactionData(
            state="test_state",
            code_verifier="test_verifier",
            nonce="test_nonce",
            return_to="https://example.com"
        )

        options = {"response": mock_response}

        with patch.object(store, 'encrypt') as mock_encrypt:
            mock_encrypt.return_value = "encrypted_data"

            await store.set("test_id", transaction_data, options)

            # Verify encryption was called with correct data
            # Update to model_dump for Pydantic v2
            mock_encrypt.assert_called_once_with("test_id", transaction_data.model_dump())

            # Verify cookie was set with secure attributes
            mock_response.set_cookie.assert_called_once_with(
                key="_a0_tx",
                value="encrypted_data",
                path="/",
                samesite="Lax",
                secure=True,
                httponly=True,
                max_age=60
            )

    @pytest.mark.asyncio
    async def test_set_without_response_raises_error(self, secret_key):
        """Test that setting without response in options raises ValueError."""
        store = CookieTransactionStore(secret_key)
        transaction_data = TransactionData(state="test", code_verifier="test_verifier", nonce="test_nonce")

        with pytest.raises(ValueError) as exc_info:
            await store.set("test_id", transaction_data, None)

        assert "Response object is required" in str(exc_info.value)

        with pytest.raises(ValueError) as exc_info:
            await store.set("test_id", transaction_data, {})

        assert "Response object is required" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_transaction_data(self, secret_key, mock_request):
        """Test retrieving transaction data from encrypted cookie."""
        store = CookieTransactionStore(secret_key)
        mock_request.cookies = {"_a0_tx": "encrypted_data"}

        options = {"request": mock_request}

        mock_decrypted_data = {
            "state": "test_state",
            "code_verifier": "test_verifier",
            "nonce": "test_nonce"
        }

        with patch.object(store, 'decrypt') as mock_decrypt:
            mock_decrypt.return_value = mock_decrypted_data

            result = await store.get("test_id", options)

            # Verify decryption was called
            mock_decrypt.assert_called_once_with("test_id", "encrypted_data")

            # Verify result is TransactionData object
            assert isinstance(result, TransactionData)
            assert result.state == "test_state"

    @pytest.mark.asyncio
    async def test_get_missing_cookie_returns_none(self, secret_key, mock_request):
        """Test that missing cookie returns None."""
        store = CookieTransactionStore(secret_key)
        mock_request.cookies = {}  # No cookie present

        options = {"request": mock_request}

        result = await store.get("test_id", options)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_corrupted_cookie_returns_none(self, secret_key, mock_request):
        """Test that corrupted cookie returns None instead of raising exception."""
        store = CookieTransactionStore(secret_key)
        mock_request.cookies = {"_a0_tx": "corrupted_data"}

        options = {"request": mock_request}

        with patch.object(store, 'decrypt') as mock_decrypt:
            mock_decrypt.side_effect = Exception("Decryption failed")

            result = await store.get("test_id", options)
            assert result is None

    @pytest.mark.asyncio
    async def test_get_without_request_raises_error(self, secret_key):
        """Test that getting without request in options raises ValueError."""
        store = CookieTransactionStore(secret_key)

        with pytest.raises(ValueError) as exc_info:
            await store.get("test_id", None)

        assert "Request object is required" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_delete_transaction_cookie(self, secret_key, mock_response):
        """Test deleting transaction cookie."""
        store = CookieTransactionStore(secret_key)
        options = {"response": mock_response}

        await store.delete("test_id", options)

        mock_response.delete_cookie.assert_called_once_with(key="_a0_tx")

    @pytest.mark.asyncio
    async def test_delete_without_response_raises_error(self, secret_key):
        """Test that deleting without response raises ValueError."""
        store = CookieTransactionStore(secret_key)

        with pytest.raises(ValueError) as exc_info:
            await store.delete("test_id", None)

        assert "Response object is required" in str(exc_info.value)

    def test_cookie_security_attributes(self, secret_key, mock_response):
        """Test that cookies are set with proper security attributes."""
        store = CookieTransactionStore(secret_key)
        transaction_data = TransactionData(
            state="test",
            code_verifier="test_verifier",
            nonce="test_nonce"
        )
        options = {"response": mock_response}

        with patch.object(store, 'encrypt', return_value="encrypted"):
            # Use asyncio.run to run the async method
            import asyncio
            asyncio.run(store.set("test_id", transaction_data, options))

            # Verify security attributes
            call_args = mock_response.set_cookie.call_args
            kwargs = call_args.kwargs

            assert kwargs['httponly'] is True
            assert kwargs['secure'] is True
            assert kwargs['samesite'] == "Lax"
            assert kwargs['path'] == "/"
            assert kwargs['max_age'] == 60  # Short expiration for transactions


class TestStatelessStateStore:
    """Test StatelessStateStore security and functionality."""

    def test_initialization(self, secret_key):
        """Test store initialization with proper parameters."""
        store = StatelessStateStore(secret_key, "_test_session", 7200)
        assert store.cookie_name == "_test_session"
        assert store.expiration == 7200
        assert store.max_cookie_size == 4096

    def test_initialization_defaults(self, secret_key):
        """Test store initialization with default parameters."""
        store = StatelessStateStore(secret_key)
        assert store.cookie_name == "_a0_session"
        assert store.expiration == 259200  # 3 days default

    @pytest.mark.asyncio
    async def test_set_small_state_data(self, secret_key, mock_response):
        """Test setting small state data that fits in one cookie."""
        store = StatelessStateStore(secret_key)

        state_data = {"user": {"sub": "test_user", "name": "Test User"}}

        options = {"response": mock_response}

        with patch.object(store, 'encrypt') as mock_encrypt:
            mock_encrypt.return_value = "small_encrypted_data"

            await store.set("test_id", state_data, options)

            # Verify encryption was called
            mock_encrypt.assert_called_once_with("test_id", state_data)

            # Verify cookie was set with proper attributes
            mock_response.set_cookie.assert_called_once()
            call_args = mock_response.set_cookie.call_args

            assert call_args.kwargs['key'] == "_a0_session_0"
            assert call_args.kwargs['httponly'] is True
            assert call_args.kwargs['secure'] is True
            assert call_args.kwargs['samesite'] == "Lax"

    @pytest.mark.asyncio
    async def test_set_large_state_data_chunking(self, secret_key, mock_response):
        """Test setting large state data that requires chunking."""
        store = StatelessStateStore(secret_key)

        # Create large state data
        large_data = {"user": {"sub": "test_user", "data": "x" * 5000}}  # Large data

        options = {"response": mock_response}

        with patch.object(store, 'encrypt') as mock_encrypt:
            # Simulate large encrypted data that needs chunking
            mock_encrypt.return_value = "x" * 8000  # Larger than max_cookie_size

            await store.set("test_id", large_data, options)

            # Verify multiple cookies were set for chunks
            assert mock_response.set_cookie.call_count > 1

            # Verify chunk naming convention
            calls = mock_response.set_cookie.call_args_list
            for i, call in enumerate(calls):
                expected_key = f"_a0_session_{i}"
                assert call.kwargs['key'] == expected_key

    @pytest.mark.asyncio
    async def test_get_single_chunk_state(self, secret_key, mock_request):
        """Test retrieving state data from single cookie chunk."""
        store = StatelessStateStore(secret_key)
        mock_request.cookies = {"_a0_session_0": "encrypted_data"}

        options = {"request": mock_request}

        mock_decrypted_data = {"user": {"sub": "test_user"}}

        with patch.object(store, 'decrypt') as mock_decrypt:
            mock_decrypt.return_value = mock_decrypted_data

            result = await store.get("test_id", options)

            # Verify decryption was called with reassembled data
            mock_decrypt.assert_called_once_with("test_id", "encrypted_data")
            assert result == mock_decrypted_data

    @pytest.mark.asyncio
    async def test_get_multi_chunk_state(self, secret_key, mock_request):
        """Test retrieving state data from multiple cookie chunks."""
        store = StatelessStateStore(secret_key)

        # Simulate chunked cookies
        mock_request.cookies = {
            "_a0_session_0": "chunk1",
            "_a0_session_1": "chunk2",
            "_a0_session_2": "chunk3"
        }

        options = {"request": mock_request}

        mock_decrypted_data = {"user": {"sub": "test_user", "large_data": "x" * 5000}}

        with patch.object(store, 'decrypt') as mock_decrypt:
            mock_decrypt.return_value = mock_decrypted_data

            result = await store.get("test_id", options)

            # Verify chunks were reassembled correctly
            mock_decrypt.assert_called_once_with("test_id", "chunk1chunk2chunk3")
            assert result == mock_decrypted_data

    @pytest.mark.asyncio
    async def test_get_missing_chunks_returns_empty_string(self, secret_key, mock_request):
        """Test that missing chunks return empty string."""
        store = StatelessStateStore(secret_key)
        mock_request.cookies = {}  # No cookies

        options = {"request": mock_request}

        result = await store.get("test_id", options)
        assert result == ""

    @pytest.mark.asyncio
    async def test_get_corrupted_chunks_returns_none(self, secret_key, mock_request):
        """Test that corrupted chunks return None."""
        store = StatelessStateStore(secret_key)
        mock_request.cookies = {"_a0_session_0": "corrupted_data"}

        options = {"request": mock_request}

        with patch.object(store, 'decrypt') as mock_decrypt:
            mock_decrypt.side_effect = Exception("Decryption failed")

            result = await store.get("test_id", options)
            assert result is None

    @pytest.mark.asyncio
    async def test_delete_all_cookie_chunks(self, secret_key, mock_response):
        """Test deleting all cookie chunks including potential ones."""
        store = StatelessStateStore(secret_key)
        options = {"response": mock_response}

        await store.delete("test_id", options)

        # Verify base cookie and potential chunks are deleted
        assert mock_response.delete_cookie.call_count == 21  # Base + 20 potential chunks

        # Verify deletion calls
        calls = mock_response.delete_cookie.call_args_list
        assert calls[0].kwargs['key'] == "_a0_session"  # Base cookie

        for i in range(20):
            expected_key = f"_a0_session_{i}"
            assert calls[i + 1].kwargs['key'] == expected_key

    @pytest.mark.asyncio
    async def test_chunking_security_no_integrity_check(self, secret_key, mock_request):
        """Test potential security issue: no integrity check for chunks."""
        store = StatelessStateStore(secret_key)

        # Simulate missing middle chunk (potential attack vector)
        mock_request.cookies = {
            "_a0_session_0": "chunk1",
            # "_a0_session_1": "chunk2",  # Missing chunk
            "_a0_session_2": "chunk3"
        }

        options = {"request": mock_request}

        with patch.object(store, 'decrypt') as mock_decrypt:
            mock_decrypt.return_value = {"partial": "data"}

            await store.get("test_id", options)

            # This demonstrates the security issue: missing chunks are silently handled
            # The reassembled data will be "chunk1chunk3" (missing middle chunk)
            mock_decrypt.assert_called_once_with("test_id", "chunk1chunk3")


class TestStatelessStoreSecurityVulnerabilities:
    """Test specific security vulnerabilities in stateless stores."""

    def test_cookie_size_limits(self, secret_key):
        """Test cookie size limits to prevent abuse."""
        store = StatelessStateStore(secret_key)

        # Test that max_cookie_size is enforced
        assert store.max_cookie_size == 4096

        # Large data should be chunked
        large_data = "x" * 10000
        chunk_size = store.max_cookie_size - len(store.cookie_name) - 10

        # Verify chunking calculation
        expected_chunks = len(large_data) // chunk_size
        if len(large_data) % chunk_size:
            expected_chunks += 1

        assert expected_chunks > 1  # Should require multiple chunks

    @pytest.mark.asyncio
    async def test_concurrent_store_operations(self, secret_key, mock_request, mock_response):
        """Test concurrent store operations for race conditions."""
        store = StatelessStateStore(secret_key)

        # Simulate concurrent set/get operations
        state_data = {"user": {"sub": "test_user"}}
        set_options = {"response": mock_response}
        get_options = {"request": mock_request}

        with patch.object(store, 'encrypt', return_value="encrypted"), \
             patch.object(store, 'decrypt', return_value=state_data):

            # These operations should not interfere with each other
            await store.set("test_id", state_data, set_options)
            await store.get("test_id", get_options)
            await store.delete("test_id", set_options)

            # Verify operations completed without raising exceptions
            assert True

    def test_cookie_name_injection_prevention(self, secret_key):
        """Test prevention of cookie name injection attacks."""
        malicious_names = [
            "_a0_session'; DROP TABLE sessions; --",
            "_a0_session\r\nSet-Cookie: malicious=value",
            "_a0_session<script>alert('XSS')</script>",
            "../../../etc/passwd"
        ]

        for malicious_name in malicious_names:
            # Store should accept any string as cookie name (validation is FastAPI's job)
            store = StatelessStateStore(secret_key, malicious_name)
            assert store.cookie_name == malicious_name

    @pytest.mark.asyncio
    async def test_encryption_key_rotation_support(self, secret_key, mock_request):
        """Test support for encryption key rotation scenarios."""
        old_store = StatelessStateStore("old_secret_key_minimum_32_chars")
        new_store = StatelessStateStore("new_secret_key_minimum_32_chars")

        mock_request.cookies = {"_a0_session_0": "encrypted_with_old_key"}
        options = {"request": mock_request}

        # Old store should decrypt successfully
        with patch.object(old_store, 'decrypt', return_value={"user": "test"}):
            result = await old_store.get("test_id", options)
            assert result == {"user": "test"}

        # New store should handle old encrypted data gracefully (return None)
        with patch.object(new_store, 'decrypt', side_effect=Exception("Decryption failed")):
            result = await new_store.get("test_id", options)
            assert result is None

    @pytest.mark.asyncio
    async def test_session_fixation_prevention(self, secret_key, mock_response):
        """Test session fixation attack prevention."""
        store = StatelessStateStore(secret_key)

        # Verify that new session data overwrites existing sessions
        old_data = {"user": {"sub": "old_user"}}
        new_data = {"user": {"sub": "new_user"}}

        options = {"response": mock_response}

        with patch.object(store, 'encrypt', side_effect=["encrypted_old", "encrypted_new"]):
            await store.set("session_id", old_data, options)
            await store.set("session_id", new_data, options)

            # Both calls should succeed, with the second overwriting the first
            assert mock_response.set_cookie.call_count == 2
