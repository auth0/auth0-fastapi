# Docs Update Rules

A PR that adds or changes public API, configuration, routes, or integration patterns is not complete until the matching docs are updated in the same PR.

## Tracked docs

| Doc | Covers | Exists |
|-----|--------|--------|
| `README.md` | Features, installation, minimal and advanced setup, mounted routes, protecting routes, audience, MCD, session expiry, custom token exchange and passkey summaries | present |
| `EXAMPLES.md` | Not used. This repo keeps examples as per-feature guides under `examples/` | missing |
| `examples/Passkeys.md` | Passkey signup, login, identifier verification, security considerations, errors, MFA, organizations, DPoP | present |
| `examples/CustomTokenExchange.md` | Token exchange with and without a session, session transfer (STT), organization scoping, error codes | present |
| `examples/MultipleCustomDomains.md` | Domain resolvers, redirect URIs, proxy headers, session behavior, security best practices | present |
| `examples/Sessions.md` | Upstream IdP `session_expiry` handling | present |

Ask before creating `EXAMPLES.md`. New guides go in `examples/<Feature>.md` and get a link from `README.md`.

## When you change code, update these docs

| When this changes | Update |
|-------------------|--------|
| A public `AuthClient` method added, removed, renamed, or its arguments changed | `README.md` (Usage) and the feature guide in `examples/` that calls it |
| `Auth0Config` fields, defaults, or aliases | `README.md` (Setup, Routes, Usage snippets that construct `Auth0Config`) |
| Mounted routes or `mount_*` flags in `server/routes.py` | `README.md` (4. Routes) |
| Store classes or their constructor options | `README.md` (Customizing the Cookie Stores) |
| Login, callback, logout, or backchannel logout behavior | `README.md` (Features, Routes) |
| Passkey wrappers or `PasskeyError` handling | `examples/Passkeys.md` and the README Passkeys section |
| Custom token exchange or session transfer wrappers | `examples/CustomTokenExchange.md` |
| Callable `domain`, `build_request_base_url`, or MCD redirect logic | `examples/MultipleCustomDomains.md` and the README MCD section |
| Session expiry or session-read behavior | `examples/Sessions.md` |
| Errors re-exported from `auth0_fastapi.errors` or their HTTP status | The error handling section of the affected guide |
| Install requirements or minimum Python version | `README.md` (2. Installation) |
