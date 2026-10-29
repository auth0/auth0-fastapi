# Common Pitfalls

1. **`ModuleNotFoundError: auth0_server_python` during test collection.** If auth0-server-python was linked into `.venv` as an editable install from a local checkout that has since moved or been deleted, every test module fails to import. Run `poetry install` to restore the locked version, after confirming with the developer that they don't need the local link.

2. **No top-level package import.** `src/auth0_fastapi/` has no `__init__.py`, so `from auth0_fastapi import AuthClient` raises `ImportError`. Import from submodules: `auth0_fastapi.auth.auth_client`, `auth0_fastapi.config`, `auth0_fastapi.server.routes`, `auth0_fastapi.errors`, `auth0_fastapi.stores`.

3. **`Auth0Config.cookie_name` is not applied.** `AuthClient.__init__` builds the default `StatelessStateStore` with a hardcoded `cookie_name="_a0_session"`. To change the session cookie name today, pass a store explicitly. Fixing the default changes cookie names, which is an Ask First change.

4. **Unmarked async tests are skipped.** pytest-asyncio runs in strict mode (no `asyncio_mode` in `pyproject.toml`), so pytest skips an `async def test_...` without `@pytest.mark.asyncio` and only emits a warning. Copy the marker from neighbouring tests.

5. **Route registration mutates the router you pass.** `register_auth_routes(router, config)` adds route handlers to the given `APIRouter`. Calling it twice on the shared module-level `router` registers the routes twice. In tests, build a fresh `APIRouter()` per case. Enabling both `mount_connect_routes` and `mount_connected_account_routes` raises `ConfigurationError`.

6. **Dependency lists live in two files.** `pyproject.toml` drives Poetry and `poetry.lock`. `requirements.txt` drives the Snyk SCA job. A bump made in only one leaves the scan checking a different version than users install.
