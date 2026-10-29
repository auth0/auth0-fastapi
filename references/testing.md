# Testing

- **Framework:** pytest with pytest-asyncio, pytest-mock, and pytest-cov (versions in `pyproject.toml` `[tool.poetry.group.dev.dependencies]`).
- **Location:** `src/auth0_fastapi/test/test_*.py`, one file per module or feature area.
- **Coverage:** `pyproject.toml` addopts always run `--cov=auth0_fastapi --cov-report=term-missing --cov-report=html`. No coverage threshold is configured.
- **Credentials:** the default `poetry run pytest` suite is unit-only and needs no tenant or secrets.

## Conventions

- Group tests in `Test<Area>` classes (`TestLoginFlow`, `TestSessionSecurity`, `TestPasskey`) and give each test a one-line docstring.
- Put fixtures at the top of the file (`auth_config`, `mock_request`, `mock_response`, `auth_client`), not between test classes.
- pytest-asyncio runs in strict mode (no `asyncio_mode` set), so every async test needs `@pytest.mark.asyncio`.
- Use synthetic values only: `test.auth0.com`, `test_client_id`, `test_secret_key_minimum_32_characters`.
- Plain `assert` is allowed in tests (`S101` is ignored for `src/auth0_fastapi/test/**`).

## Mocking

| Layer under test | Pattern | Example |
|------------------|---------|---------|
| Routes | `Mock(spec=AuthClient)` with `AsyncMock` methods, call `register_auth_routes` on a fresh router | `test_routes.py` `mock_auth_client` fixture |
| `AuthClient` wrappers | `patch.object(auth_client.client, "<method>", new_callable=AsyncMock)` and assert the forwarded arguments | `test_auth_client.py` `TestLoginFlow` |
| `AuthClient` construction | `patch("auth0_fastapi.auth.auth_client.ServerClient")` and inspect the kwargs | `test_auth_client.py` `TestAuthClientInitialization` |
| End to end through the real `ServerClient` | Monkeypatch `httpx.AsyncClient` to use `httpx.MockTransport` with a fake Auth0 that signs ID tokens with a generated JWK | `test_passkey_http.py` `auth0` fixture |
| Stores | Mock `Request.cookies` and `Response.set_cookie`/`delete_cookie`, or a fake async backend store for `StatefulStateStore` | `test_stateless_store.py`, `test_stateful_store.py` |

Use the `httpx.MockTransport` pattern when the behavior depends on how auth0-server-python parses Auth0's HTTP response (status codes, error bodies, ID token validation). Wrapper-only changes are covered by `patch.object`.
