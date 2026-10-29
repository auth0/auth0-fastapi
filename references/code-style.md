# Code Style

## Enforced by `ruff check` (`.ruff.toml`)

- Line length 120, target `py39`.
- Rule sets: `E`, `W`, `F`, `I` (isort), `C4`, `UP`, `S` (bandit), `DTZ`, `G`, `A`, `C`.
- Per-file ignores exist for `__init__.py` re-exports, `config.py` long lines, `routes.py` complexity, and tests. Don't add new suppressions without a reason.

## Naming

- snake_case for functions, methods, variables, and `Auth0Config` fields. camelCase appears only where an external contract needs it: pydantic aliases (`clientId`, `appBaseUrl`) and query parameters or `app_state` keys (`returnTo`, `connectionScope`).
- PascalCase for classes. Errors end in `Error` and set a `code` attribute.

## Wrapper pattern

Public `AuthClient` methods forward their arguments to `ServerClient` with minimal glue, such as building an options object (`StartInteractiveLoginOptions`, `LogoutOptions`). Methods that accept `store_options` take it last and document it.

Good (`auth/auth_client.py`):

```python
    async def custom_token_exchange(
        self,
        options: CustomTokenExchangeOptions,
        store_options: dict = None,
    ) -> TokenExchangeResponse:
        """
        Performs an RFC 8693 token exchange for the given subject token.
        Does not create or modify the current session.

        Args:
            options: Subject token details and exchange parameters
                (subject_token, subject_token_type, audience, scope,
                organization, authorization_params).
            store_options: Optional options passed to the Transaction and State
                Store. Only required when using Multiple Custom Domains, where
                the domain resolver needs the incoming request.

        Returns:
            The raw TokenExchangeResponse (access_token, expires_in).

        Raises:
            CustomTokenExchangeError: If the exchange fails or the subject
                token parameters are invalid (see CustomTokenExchangeErrorCode).
        """
        return await self.client.custom_token_exchange(options, store_options=store_options)
```

Bad:

```python
    async def custom_token_exchange(self, options, store_options: dict | None = None):
        # Call the token endpoint directly
        async with httpx.AsyncClient() as http:
            resp = await http.post(f"https://{self.config.domain}/oauth/token", data=options)
        logger.info("token exchange result %s", resp.json())
        return resp.json()
```

The bad version reimplements protocol logic owned by auth0-server-python, logs tokens, uses `X | None` (breaks on Python 3.9 where evaluated), drops the return type, and has a narrating comment instead of a docstring.

## Patterns

- **Adapter:** `AuthClient` wraps `ServerClient`. The stores subclass `TransactionStore`/`StateStore` from `auth0_server_python.store.abstract` and read `request`/`response` from `store_options`.
- **Config-driven routes:** `register_auth_routes(router, config)` mounts route groups by `mount_routes`, `mount_connect_routes`, and `mount_connected_account_routes`, and raises `ConfigurationError` on invalid combinations.
- **Dependency injection:** routes get the client through `Depends(get_auth_client)`, which reads `request.app.state.auth_client`. Apps protect routes with `Depends(auth_client.require_session)`.
- **Error mapping:** `register_exception_handlers(app)` installs `auth0_exception_handler`, which maps `Auth0Error` subclasses to HTTP statuses with a `{"error", "message"}` body.

## Comments and docs

- No inline comments that narrate a self-explanatory line.
- Plain hyphens only in code, docstrings, and docs. No em or en dashes.
- Public docs and docstrings state only behavior that Auth0's public docs or the auth0-server-python public API confirm. Don't describe Auth0 backend internals.
