# Custom Token Exchange

Custom Token Exchange lets your FastAPI backend exchange a token from an external identity provider or legacy authentication system for Auth0 tokens, without a browser redirect. This implements **OAuth 2.0 Token Exchange** ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)).

> **NOTE**: For configuration requirements on the Auth0 side (token-exchange profiles, Actions, reserved namespaces), see the [official Auth0 documentation](https://auth0.com/docs/authenticate/custom-token-exchange).

`AuthClient` exposes two methods for this:

| Method | Session effect | Use case |
|---|---|---|
| `custom_token_exchange()` | None. The current session is untouched. | Calling a downstream API with a different audience/scope |
| `login_with_custom_token_exchange()` | Establishes a full Auth0 session, same as completing `/auth/callback` | Logging a user into your app using a token issued by an external system |

Both methods are programmatic — there is no dedicated route mounted by the SDK. You call them from your own route handler.

## 1. Basic Token Exchange (no session)

Exchange a token for Auth0 tokens without affecting the caller's session:

```python
from fastapi import APIRouter, Request, Response
from auth0_server_python.auth_types import CustomTokenExchangeOptions

from auth0_fastapi.auth.auth_client import AuthClient

router = APIRouter()

@router.post("/api/exchange")
async def exchange_token(request: Request, response: Response):
    auth_client: AuthClient = request.app.state.auth_client

    result = await auth_client.custom_token_exchange(
        CustomTokenExchangeOptions(
            subject_token="token-from-external-system",
            subject_token_type="urn:acme:legacy-session-token",
            audience="https://downstream-api.example.com",
            scope="read:data write:data",
        ),
        store_options={"request": request, "response": response},
    )

    return {
        "access_token": result.access_token,
        "expires_in": result.expires_in,
    }
```

`store_options` is optional here — `custom_token_exchange()` does not read or write any cookies. Pass it (as `{"request": request, "response": response}`) only if you've configured [Multiple Custom Domains](../README.md#multiple-custom-domains-mcd) with a domain resolver, since the resolver needs the incoming request to pick a domain. Otherwise it can be omitted entirely, which is useful for service-to-service or background-job scenarios where there is no `Request`/`Response` at all:

```python
from auth0_server_python.auth_types import CustomTokenExchangeOptions

result = await auth_client.custom_token_exchange(
    CustomTokenExchangeOptions(
        subject_token="service-token",
        subject_token_type="urn:acme:service-token",
        audience="https://downstream-api.example.com",
    )
)
```

## 2. Login with Custom Token Exchange (establishes a session)

Exchange a token AND log the user into your FastAPI app:

```python
from fastapi import APIRouter, Request, Response
from auth0_server_python.auth_types import LoginWithCustomTokenExchangeOptions

router = APIRouter()

@router.post("/auth/token-exchange")
async def token_exchange_login(request: Request, response: Response):
    auth_client: AuthClient = request.app.state.auth_client

    result = await auth_client.login_with_custom_token_exchange(
        LoginWithCustomTokenExchangeOptions(
            subject_token="token-from-external-idp",
            subject_token_type="urn:acme:corporate-idp-token",
        ),
        store_options={"request": request, "response": response},
    )

    user = result.state_data["user"]
    return {"user": user}
```

Passing `response` in `store_options` is required. The session store uses it to write the `Set-Cookie` header. Omitting it raises a `ValueError` from the underlying state store.

Once this route completes, protected routes work immediately:

```python
from fastapi import Depends

@router.get("/api/me")
async def get_profile(session: dict = Depends(auth_client.require_session)):
    return {"user": session["user"]}
```

> **TIP**: Use `login_with_custom_token_exchange()` for user-migration or external-IdP login flows. Use `custom_token_exchange()` for pure service-to-service or downstream-API scenarios where the caller's own session should not change.

## 3. Scoping the Exchange to an Organization

Pass `organization` (an org ID like `org_abc123`, or an org name) to scope the exchange to a specific
Auth0 Organization. The SDK forwards it to Auth0. Auth0 rejects the exchange with `CustomTokenExchangeError`
if the subject is not a member of that organization.

```python
result = await auth_client.login_with_custom_token_exchange(
    LoginWithCustomTokenExchangeOptions(
        subject_token="token-from-external-idp",
        subject_token_type="urn:acme:corporate-idp-token",
        organization="org_abc123",
    ),
    store_options={"request": request, "response": response},
)
```

## 4. Error Handling

Register the SDK's exception handler once, and `CustomTokenExchangeError` will be mapped to an HTTP JSON response automatically:

```python
from auth0_fastapi.errors import register_exception_handlers

register_exception_handlers(app)
```

Or handle it inline if a route needs custom behavior:

```python
from fastapi import HTTPException
from auth0_fastapi.errors import CustomTokenExchangeError, CustomTokenExchangeErrorCode

@router.post("/api/exchange")
async def exchange_token(request: Request, response: Response):
    try:
        result = await auth_client.custom_token_exchange(
            CustomTokenExchangeOptions(
                subject_token=request.headers.get("x-external-token", ""),
                subject_token_type="urn:acme:legacy-session-token",
                organization="org_abc123",
            ),
            store_options={"request": request, "response": response},
        )
    except CustomTokenExchangeError as e:
        if e.code == CustomTokenExchangeErrorCode.INVALID_TOKEN_FORMAT:
            raise HTTPException(status_code=400, detail="Invalid subject token")
        raise

    return {"access_token": result.access_token}
```

### Common Error Codes

See the [auth0-server-python Custom Token Exchange doc](https://github.com/auth0/auth0-server-python/blob/main/examples/CustomTokenExchange.md#common-error-codes) for the full, up-to-date list of `CustomTokenExchangeErrorCode` values and what triggers each one.

`INVALID_TOKEN_FORMAT` is raised client-side before any network call for an empty or whitespace-only `subject_token`, or one with a `"Bearer "` prefix. Other malformed-but-nonempty values (including a `subject_token_type` that isn't a valid URI) are not checked client-side and are sent to Auth0, which rejects them.

When `organization` is set and the subject is not a member, Auth0 rejects the exchange as `CustomTokenExchangeError`.

## 5. Token Type URIs

`subject_token_type` accepts any URI, either a standard RFC 8693 URN (e.g. `urn:ietf:params:oauth:token-type:jwt`) or your own namespace (e.g. `urn:acme:legacy-session-token`).

See the [auth0-server-python Custom Token Exchange doc](https://github.com/auth0/auth0-server-python/blob/main/examples/CustomTokenExchange.md) for the full set of standard token-type URNs, and the [official Auth0 documentation](https://auth0.com/docs/authenticate/custom-token-exchange) for which namespaces are reserved and cannot be used as a *custom* `subject_token_type` when configuring a token-exchange profile in the Auth0 Dashboard.

## Additional Resources

- [Auth0 Custom Token Exchange Documentation](https://auth0.com/docs/authenticate/custom-token-exchange)
- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [auth0-server-python: Custom Token Exchange](https://github.com/auth0/auth0-server-python/blob/main/examples/CustomTokenExchange.md) — the underlying protocol implementation this SDK wraps
