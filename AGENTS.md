# AI Agent Guidelines for auth0-fastapi

## Overview

auth0-fastapi is the FastAPI adapter over auth0-server-python for server-side web apps. It consists of thin wrappers plus the routes, cookie stores, and tests around them.

---

## Project Structure

```
auth0-fastapi/
├── src/auth0_fastapi/            # The package (no top-level __init__.py, import from submodules)
│   ├── config.py                 # Auth0Config pydantic model (integrator settings)
│   ├── auth/auth_client.py       # AuthClient: public API, each method delegates to ServerClient
│   ├── server/routes.py          # router + register_auth_routes (/auth/login, /callback, /logout, ...)
│   ├── errors/__init__.py        # Re-exported auth0-server-python errors, ConfigurationError, exception handler
│   ├── stores/                   # CookieTransactionStore, StatelessStateStore, StatefulStateStore
│   ├── util/__init__.py          # URL helpers incl. to_safe_redirect and build_request_base_url
│   └── test/                     # pytest suite (tests live inside the package)
├── examples/                     # Feature guides: Passkeys, CustomTokenExchange, MultipleCustomDomains, Sessions
├── references/                   # Agent reference docs
├── .github/workflows/            # tests.yml (lint + tests), sca_scan.yml (Snyk), codeql.yml, publish.yml, claude-code-review.yml
├── pyproject.toml                # Poetry manifest, pytest addopts (coverage)
├── requirements.txt              # Pip copy of runtime and test deps, installed by the SCA workflow
├── .ruff.toml                    # Lint config (line length 120, py39 target, bandit rules)
├── .version                      # Release version read by publish.yml (release commits also bump pyproject.toml)
└── CHANGELOG.md                  # Release notes, written during the release flow
```

---

## Boundaries

### Always Do

- Run `poetry run ruff check .` and `poetry run pytest` before committing. CI runs both on Python 3.9 to 3.12.
- Make surgical changes. Touch only what the request requires, and don't refactor or reformat adjacent code that isn't broken.
- Keep `AuthClient` methods as thin pass-throughs to `self.client` (`ServerClient`). Protocol, token, and crypto logic belongs in auth0-server-python.
- Add a new feature's public methods at the end of `AuthClient`, and keep private helpers grouped together, never between public methods.
- Write docstrings as a short summary, then `Args`, `Returns`, `Raises`, matching the passkey and custom token exchange methods.
- Add unit tests in `src/auth0_fastapi/test/` for every change, and mark async tests with `@pytest.mark.asyncio`.
- Raise or re-export typed errors from `auth0_fastapi.errors`. Map new `Auth0Error` subclasses in `auth0_exception_handler` when they need a non-400 status.
- Pass every new user-supplied redirect target (`returnTo` and similar) through `to_safe_redirect` before it is stored or redirected to.
- Update `README.md` and the matching `examples/*.md` guide in the same PR when changing the public API, `Auth0Config` options, mounted routes, or supported integration patterns.
- When a runtime or test dependency changes, update both `pyproject.toml` and `requirements.txt` (the SCA workflow installs `requirements.txt` before the Snyk scan).
- Use Python 3.9 compatible syntax: `Optional[X]` and `Union[X, Y]`, not `X | Y`, in annotations that FastAPI or pydantic evaluate.

### Ask First

- Any breaking change. Never make one on your own initiative. Stop and ask the maintainer before writing it.
- Adding, removing, or bumping a dependency, including the `auth0-server-python` floor.
- Changing a public signature in `AuthClient`, `Auth0Config`, `register_auth_routes`, the stores, or `auth0_fastapi.errors`.
- Changing a mounted route path, its query or body contract, or its status codes.
- Changing cookie names, cookie attributes, chunking, or session expiry. The stores look sessions up by cookie name, so renaming a cookie makes existing sessions unreadable.
- Changing the status-code mapping in `auth0_exception_handler`.
- Changing CI workflows, `.github/actions/`, `.ruff.toml`, or `.snyk`.
- Running `ruff format` on any file. CI doesn't enforce it, and it can rewrite lines the task didn't touch.

### Never Do

- Commit secrets, API keys, tokens, or a real `.env`. Test fixtures use synthetic values only.
- Log or echo tokens, session data, `client_secret`, or `secret`, including in error messages and exception `detail`.
- Weaken cookie flags (`secure`, `httponly`, `samesite`) or the issuer check in `StatefulStateStore.delete_by_logout_token`.
- Add a redirect to a URL built from request input without `to_safe_redirect`.
- Hand-edit `poetry.lock`, or bump the version in `.version` or `pyproject.toml` outside the release flow.
- Hand-edit files in `.venv/`, `build/`, `dist/`, `htmlcov/`, `.pytest_cache/`, or `__pycache__/`.
- Remove or skip failing tests without fixing them.

---

## Security Considerations

- **App type:** confidential client (server-side web app). `client_secret` and `secret` stay server-side and come from the environment, never source.
- **Delegated protocol logic:** authorize, token exchange, logout token, and ID token handling all run in `ServerClient` from auth0-server-python. The two cookie stores encrypt with that package's store `encrypt`/`decrypt`, keyed by `Auth0Config.secret`. Don't add crypto here.
- **PKCE and CSRF:** `ServerClient.start_interactive_login` generates the S256 PKCE challenge and a random `state`, and `ServerClient.complete_interactive_login` looks up the transaction by `state` (as of auth0-server-python 1.0.0b20, the dependency floor). This package sets no CORS or CSP headers.
- **DPoP:** in `AuthClient`, only `signin_with_passkey` accepts a `dpop_key`, which it passes through to `ServerClient` (`examples/Passkeys.md`, section 6).
- **Cookies:** the transaction cookie `_a0_tx` is `secure`, `httponly`, `samesite=Lax`, `max_age=60` (`stores/cookie_transaction_store.py`). The stateless session is chunked into `_a0_session_<n>` cookies that are `secure`, `httponly`, `samesite=Lax` (`stores/stateless_state_store.py`).
- **Stateful store:** `StatefulStateStore` keeps session data in the backend store and tracks the session with a session-ID cookie (`stores/stateful_state_store.py`). Any new store sets `secure`, `httponly`, and `samesite` on its cookies.
- **Open redirect:** `to_safe_redirect` (`util/__init__.py`) only allows the same origin as `app_base_url` (or the request base URL under MCD). `/auth/callback` applies it when it redirects, and the legacy `/auth/connect` and `/auth/unconnect` apply it before they store `returnTo`. Don't change how existing routes handle `returnTo` without asking.
- **Multiple Custom Domains:** under MCD the request base URL is built from `x-forwarded-host` and `x-forwarded-proto`, so deploy behind a trusted proxy. Domain resolvers must map hosts through an allowlist (see `examples/MultipleCustomDomains.md`, Security Best Practices).
- **Backchannel logout:** `StatefulStateStore.delete_by_logout_token` skips sessions whose stored domain doesn't match the token `iss` when both are present, which prevents cross-domain deletion under MCD.
- **Error responses:** `auth0_exception_handler` returns only `error` (code) and `message`. New code raises typed errors and lets the registered handler map them, and doesn't put raw exception text in `HTTPException` detail.
- **Lint:** ruff's bandit rules (`S`) run in CI, with the ignores listed in `.ruff.toml`. In auth code paths, handle errors explicitly and raise typed errors rather than swallowing exceptions.

---

## Commands

Install with `poetry install`, lint with `poetry run ruff check .`, and test with `poetry run pytest`. See [references/commands.md](references/commands.md) for the full command list. Read it only when you need to build, lint, or test.

## Testing

The default `poetry run pytest` suite needs no credentials. HTTP is mocked with `unittest.mock` or `httpx.MockTransport`. See [references/testing.md](references/testing.md) for layout, fixtures, mocking patterns, and coverage. Read it when you write or debug tests.

## Code Style

`ruff check` enforces 120-character lines and isort import order. Naming isn't linted, but the code uses snake_case functions and fields and PascalCase classes. See [references/code-style.md](references/code-style.md) for examples and patterns. Read it when you add or change public API.

## Git Workflow

Conventional commit subjects (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `build:`, `chore:`, `revert:`) on a typed branch such as `feat/<topic>`. See [references/git-workflow.md](references/git-workflow.md) for branch and PR conventions. Read it before you commit or open a PR.

## Common Pitfalls

Gotchas include import paths and where the session cookie name is set. See [references/pitfalls.md](references/pitfalls.md). Read it when something fails unexpectedly or before you touch config, stores, or imports.

## Docs Update Rules

Docs ship in the same PR as the code they describe. See [references/docs-update.md](references/docs-update.md) for the tracked docs and the code-to-docs mapping. Read it before you finish any change to public API, config, or routes.
