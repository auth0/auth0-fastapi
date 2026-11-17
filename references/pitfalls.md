# Common Pitfalls

1. **No top-level package import.** `src/auth0_fastapi/` has no `__init__.py`, so `from auth0_fastapi import AuthClient` raises `ImportError`. Import from submodules: `auth0_fastapi.auth.auth_client`, `auth0_fastapi.config`, `auth0_fastapi.server.routes`, `auth0_fastapi.errors`, `auth0_fastapi.stores`.

2. **Set the session cookie name on the store, not on `Auth0Config`.** `AuthClient.__init__` builds the default `StatelessStateStore` with `cookie_name="_a0_session"`. To use a different name, pass your own store to `AuthClient`. Changing the default changes cookie names, which is an Ask First change.

3. **Unmarked async tests are skipped.** pytest-asyncio runs in strict mode (no `asyncio_mode` in `pyproject.toml`), so pytest skips an `async def test_...` without `@pytest.mark.asyncio` and only emits a warning. Copy the marker from neighbouring tests.

4. **Route registration mutates the router you pass.** `register_auth_routes(router, config)` adds route handlers to the given `APIRouter`. Calling it twice on the shared module-level `router` registers the routes twice. In tests, build a fresh `APIRouter()` per case. Enabling both `mount_connect_routes` and `mount_connected_account_routes` raises `ConfigurationError`.

5. **Dependency lists live in two files.** `pyproject.toml` drives Poetry and `poetry.lock`. `requirements.txt` is what the SCA workflow installs before its Snyk scan. Update both so the scanned dependencies match what Poetry resolves.
