# Sessions

## Session expiry from upstream IdP

When an enterprise connection has the **"Use ID Token for Session Expiry"** option enabled (`id_token_session_expiry_supported: true`), Auth0 emits a `session_expiry` claim in the ID token issued to your application. It is an absolute Unix timestamp (integer seconds) that asserts the upstream IdP's session ceiling - the point past which the user's session must not be trusted, even if your own idle/absolute timeouts would still allow it.

The SDK treats this claim as a hard ceiling on the local session. All of the enforcement lives in the underlying `auth0-server-python` SDK, and `auth0-fastapi` delegates to it - so **you do not need to write any session-expiry code**. This guide is about what to expect and the one thing to watch out for.

### How it behaves in auth0-fastapi

- At login (the mounted `/auth/callback` route), the SDK reads `session_expiry` from the ID token and stores it on the session. It round-trips through the encrypted session cookie automatically.
- A 30-second negative clock-skew leeway is applied - the session is treated as expired slightly *before* the wall-clock ceiling.
- Once the ceiling is reached, the session behaves exactly like "no session": `get_session()` and `get_user()` return `None` (and clear the cookie), and `get_access_token()` raises `SessionExpiredError` without attempting a refresh.
- The ceiling is fixed at login and preserved across token refreshes.

Because an expired ceiling looks identical to "not logged in," the `require_session` dependency you already use keeps working with no change - it raises the same **401** it raises for any unauthenticated request:

```python
from fastapi import Depends, Request, Response
from auth0_fastapi.auth.auth_client import AuthClient

@app.get("/profile")
async def profile(request: Request, response: Response,
                  session=Depends(auth_client.require_session)):
    # Once the ceiling passes, require_session raises 401 just as it would for a
    # user who never logged in. Your existing redirect-to-login path handles it.
    return {"user": session.get("user")}
```

If you read the session yourself instead of using `require_session`, treat a `None` result as logged-out and send the user through `/auth/login`:

```python
session = await auth_client.client.get_session(
    store_options={"request": request, "response": response}
)
if not session:
    return RedirectResponse("/auth/login")
```

### Prerequisite

This is gated entirely on the connection option. Enable **"Use ID Token for Session Expiry"** on the OIDC / Okta enterprise connection (Dashboard, Management API, or Terraform). Only `oidc` / `okta` strategy connections accept it. Until it is enabled, no `session_expiry` claim is emitted and session behavior is unchanged.

### Reading the value (optional)

The ceiling is just another value on the session, so you can read it for your own UI (for example, a "session ending soon" banner):

```python
session = await auth_client.client.get_session(
    store_options={"request": request, "response": response}
)
ceiling = (session or {}).get("internal", {}).get("session_expires_at")  # Unix seconds, or None
```

> [!WARNING]
> **Add a null check when upgrading.** Once the connection option is on, `get_session()` / `get_user()` can return `None` for a user who *was* logged in, the moment the ceiling passes. Code that assumed these always return a value after login must handle `None` (using `require_session` does this for you).

> [!WARNING]
> **Do not cache the ceiling.** `session_expires_at` is only meaningful relative to the wall clock at read time. Re-read it from the session each time; never copy it into a separate long-lived store.

> [!IMPORTANT]
> **Keep idle/absolute timeouts separate.** `session_expiry` is an additional ceiling layered on top of your existing timeouts, not a replacement. The session ends at whichever limit is reached first; do not collapse them into one value.
