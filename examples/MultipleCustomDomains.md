# Multiple Custom Domains (MCD)

MCD lets you resolve the Auth0 domain per request while keeping a single `AuthClient` instance. This is useful when your application uses multiple custom domains configured on the same Auth0 tenant.

> **Important:** MCD supports multiple custom domains on a **single Auth0 tenant**. It does not support connecting to multiple Auth0 tenants from a single application. Each custom domain must belong to the same Auth0 tenant. Using domains from different Auth0 tenants is not supported and will result in authentication failures.

**Example:**
- `https://brand-1.yourapp.com` → Custom domain: `login.brand-1.com`
- `https://brand-2.yourapp.com` → Custom domain: `login.brand-2.com`

MCD is enabled by providing a **domain resolver function** instead of a static domain string.

See [Security Best Practices](#security-best-practices) for important guidance on configuring your resolver safely.

## Basic Setup

### 1. Define a Domain Resolver

The domain resolver is an async function that receives request context and returns the appropriate Auth0 domain:

```python
from auth0_server_python.auth_types import DomainResolverContext

DOMAIN_MAP = {
    "brand-1.yourapp.com": "login.brand-1.com",
    "brand-2.yourapp.com": "login.brand-2.com",
}
DEFAULT_DOMAIN = "login.yourapp.com"

async def domain_resolver(context: DomainResolverContext) -> str:
    """
    Resolve Auth0 domain based on incoming request.

    Args:
        context.request_url: Full request URL (e.g., "https://brand-1.yourapp.com/auth/login")
        context.request_headers: Dict of request headers

    Returns:
        Auth0 domain string (e.g., "login.brand-1.com")
    """
    if context.request_headers:
        host = context.request_headers.get("host", "").split(":")[0]
        return DOMAIN_MAP.get(host, DEFAULT_DOMAIN)

    return DEFAULT_DOMAIN
```

### 2. Configure Auth0Config

Pass the resolver function instead of a static domain string:

```python
from auth0_fastapi import Auth0Config, AuthClient

config = Auth0Config(
    domain=domain_resolver,  # Callable triggers MCD mode
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    app_base_url="https://yourapp.com",
    secret="your-32-character-secret-key!!",
)

auth_client = AuthClient(config)
```

## Redirect URI Requirements

In resolver mode, the SDK builds the `redirect_uri` dynamically from the request host. You do not need to set it manually. If you override `redirect_uri` in `authorization_params`, the SDK uses your value as-is.

> **Note:** In resolver mode, MCD needs an ID token in the callback so the SDK can validate
> the `iss` claim. The `openid` scope is required to receive an ID token. Ensure `openid` is
> included in your `authorization_params.scope`.

## Usage Patterns

### Pattern 1: Host Header Mapping (Recommended)

Map request hostnames directly to Auth0 domains using an allowlist:

```python
DOMAIN_MAP = {
    "brand-1.yourapp.com": "login.brand-1.com",
    "brand-2.yourapp.com": "login.brand-2.com",
    "brand-3.yourapp.com": "login.brand-3.com",
}

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    return DOMAIN_MAP.get(host, DEFAULT_DOMAIN)
```

### Pattern 2: Subdomain Extraction

> **Warning:** This pattern constructs the Auth0 domain from raw header input. An attacker who controls the `Host` header can influence the resolved domain. Use an allowlist (Pattern 1) for production deployments. See [Security Best Practices](#security-best-practices).

```python
async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]

    # Extract subdomain: "brand-1.yourapp.com" -> "brand-1"
    parts = host.split(".")
    if len(parts) >= 3:
        subdomain = parts[0]
        return f"login.{subdomain}.com"  # attacker sends Host: evil.yourapp.com -> login.evil.com

    return DEFAULT_DOMAIN
```

### Pattern 3: Database Lookup

Fetch domain from database:

```python
async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    subdomain = host.split(".")[0]

    # Lookup in database (use caching in production)
    domain_config = await get_domain_config(subdomain)
    if domain_config:
        return domain_config.auth0_domain

    return DEFAULT_DOMAIN
```

### Pattern 4: Environment-Based Configuration

Use environment variables for domain configuration:

```python
import os
import json

# Load from environment: DOMAIN_MAP='{"brand-1": "login.brand-1.com", "brand-2": "login.brand-2.com"}'
DOMAIN_MAP = json.loads(os.environ.get("DOMAIN_MAP", "{}"))

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    subdomain = host.split(".")[0]
    return DOMAIN_MAP.get(subdomain, os.environ.get("DEFAULT_AUTH0_DOMAIN"))
```

## Proxy Headers

When running behind a reverse proxy (nginx, load balancer), use forwarded headers:

```python
async def domain_resolver(context: DomainResolverContext) -> str:
    headers = context.request_headers or {}

    # Prefer x-forwarded-host over host
    host = headers.get("x-forwarded-host") or headers.get("host", "")
    host = host.split(":")[0]  # Remove port

    return DOMAIN_MAP.get(host, DEFAULT_DOMAIN)
```

## Auth0 Dashboard Configuration

For MCD to work, configure your Auth0 application:

1. **Allowed Callback URLs**: Add all callback URLs
   ```
   https://brand-1.yourapp.com/auth/callback
   https://brand-2.yourapp.com/auth/callback
   ```

2. **Allowed Logout URLs**: Add all base URLs
   ```
   https://brand-1.yourapp.com
   https://brand-2.yourapp.com
   ```

3. **Allowed Web Origins** (if using SPA features):
   ```
   https://brand-1.yourapp.com
   https://brand-2.yourapp.com
   ```

## Error Handling

Handle domain resolver errors gracefully:

```python
from auth0_server_python.error import DomainResolverError

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]

    domain = DOMAIN_MAP.get(host)
    if not domain:
        # Option 1: Return default
        return DEFAULT_DOMAIN

        # Option 2: Raise error (will return 500 to user)
        # raise DomainResolverError(f"Unknown host: {host}")

    return domain
```

## How It Works

When MCD is enabled, the SDK:

1. **Login**: Resolves domain from request, builds dynamic `redirect_uri`, stores `domain` in transaction
2. **Callback**: Retrieves `domain` from transaction, derives issuer from OIDC metadata, exchanges code with correct token endpoint, validates issuer
3. **Session**: Stores `domain` field in session for future requests
4. **Token Refresh**: Uses session's stored domain (not current request domain)
5. **Logout**: Resolves current domain for logout URL

## Session Behavior in Resolver Mode

In resolver mode, sessions are bound to the domain that created them. On each request, the SDK compares the session's stored domain against the current resolved domain. If the domains do not match:

- `get_user()` and `get_session()` return `None`.
- `get_access_token()` raises `AccessTokenError` (code `MISSING_SESSION_DOMAIN` or `DOMAIN_MISMATCH`).
- `get_access_token_for_connection()` raises `AccessTokenForConnectionError` (same codes as above).
- `start_link_user()` and `start_unlink_user()` raise `StartLinkUserError`.
- Token refresh uses the session's stored domain, not the current request domain.

All domain mismatch errors use the message: **"Session domain does not match the current domain."**

> **Note:** If a login was started before the switch to resolver mode and completes after, the SDK falls back to the current resolved domain for token exchange. The resulting session will store the resolved domain and work normally going forward.

## Legacy Sessions

When moving from a static domain setup to resolver mode, existing sessions can continue
to work if the resolver returns the same Auth0 domain that was used for those legacy sessions.

The SDK uses a three-tier fallback to determine the session's domain:

1. **`session.domain`** — new sessions created after MCD was enabled store this field.
2. **Static domain** — if a static `domain` string was configured, it is used as a fallback.
3. **User's issuer claim** — the hostname is extracted from the `iss` claim in the user's
   ID token (e.g., `https://login.brand-1.com/` yields `login.brand-1.com`).

This means legacy sessions created before MCD support will still work as long as the
resolver returns a domain that matches one of the fallback values. In most cases, the
issuer claim already matches the Auth0 domain, so no re-authentication is needed.

If the resolver returns a different domain that does not match any tier, the SDK treats
the session as belonging to another domain and the user will need to sign in again. This
is intentional to keep sessions isolated per domain.

## Discovery Cache

The SDK caches OIDC metadata and JWKS per domain in memory (LRU eviction, 600-second TTL, up to 100 domains). This avoids repeated network calls when serving multiple domains. The cache is shared across all requests to the same `AuthClient` instance.

Most applications can keep the defaults, but you may want to adjust in these cases:
- Increase `max_entries` if one process handles more than 100 distinct Auth0 domains during the TTL window. This is most common in MCD deployments that work with many custom domains.
- Decrease `max_entries` if memory usage matters more than avoiding repeated discovery.
- Increase TTL if the same domains are reused frequently and you want to reduce repeated discovery and JWKS fetches after cache entries expire.
- Decrease TTL if you want the SDK to pick up Auth0 metadata or signing key changes sooner.

Rule of thumb: set `max_entries` to cover the number of distinct Auth0 domains a single process is expected to use during the TTL window, with some headroom.

## Security Best Practices

> **The domain resolver is a security-critical component.** A misconfigured resolver can lead to authentication bypass on the relying party (RP) or expose the application to Server-Side Request Forgery (SSRF). The SDK trusts the resolved domain to fetch OIDC metadata and verification keys. It is the customer's responsibility to ensure the resolver cannot be influenced by untrusted input.

**Single Tenant Limitation:**
The domain resolver is intended solely for multiple custom domains belonging to the same Auth0 tenant. It is not a supported mechanism for connecting multiple Auth0 tenants to a single application.

- **Session Isolation**: Sessions are bound to their origin domain. A session created on one custom domain cannot be used on another.
- **Issuer Validation**: Token issuer is validated against the expected domain (with normalization for trailing slashes and case)
- **Token Refresh**: Refresh tokens are used with their original domain's token endpoint
- **Redirect URI Protection**: Auth0 rejects authorization requests where `redirect_uri` is not in the application's Allowed Callback URLs, preventing redirect-based attacks even if host headers are spoofed.

### Use an Allowlist in Your Resolver

The SDK passes request headers to your domain resolver via `DomainResolverContext`. These headers come directly from the HTTP request and can be spoofed by an attacker (e.g., `Host: evil.com` or `X-Forwarded-Host: evil.com`).

The SDK uses the resolved domain to fetch OIDC metadata and JWKS. If an attacker can influence the resolved domain, they could point the SDK at an OIDC provider they control.

**Always use a mapping or allowlist — never construct domains from raw header values:**

```python
# Safe: allowlist lookup — unknown hosts fall back to default
DOMAIN_MAP = {
    "brand-1.yourapp.com": "login.brand-1.com",
    "brand-2.yourapp.com": "login.brand-2.com",
}

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    return DOMAIN_MAP.get(host, DEFAULT_DOMAIN)
```

```python
# Risky: constructs domain from raw input — attacker can influence resolved domain
async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    subdomain = host.split(".")[0]
    return f"login.{subdomain}.com"  # attacker sends Host: evil.yourapp.com -> login.evil.com
```

### Secure Proxy Requirement

When using Multiple Custom Domains (MCD), your application must be deployed behind a secure reverse proxy (e.g., Cloudflare, Nginx, or AWS ALB). The proxy must be configured to sanitize and overwrite `Host` and `X-Forwarded-Host` headers before they reach your application.

Without a trusted proxy layer to validate these headers, an attacker can manipulate the domain resolution process. This can result in authentication bypass or Server-Side Request Forgery (SSRF).

### Trust Forwarded Headers Only Behind a Proxy

If your application is directly exposed to the internet (not behind a reverse proxy), do not trust `x-forwarded-host` or `x-forwarded-proto` — any client can set these headers.

Only use forwarded headers when your application runs behind a trusted reverse proxy (nginx, AWS ALB, Cloudflare, etc.) that sets these headers and strips any client-provided values.

```python
# Only trust x-forwarded-host if behind a trusted proxy
async def domain_resolver(context: DomainResolverContext) -> str:
    headers = context.request_headers or {}

    if BEHIND_TRUSTED_PROXY:
        host = headers.get("x-forwarded-host") or headers.get("host", "")
    else:
        host = headers.get("host", "")

    host = host.split(":")[0]
    return DOMAIN_MAP.get(host, DEFAULT_DOMAIN)
```

Consider adding `TrustedHostMiddleware` to reject unexpected `Host` headers:

```python
from starlette.middleware.trustedhost import TrustedHostMiddleware

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["brand-1.yourapp.com", "brand-2.yourapp.com"]
)
```

## Complete Example

```python
# main.py
import os
from fastapi import FastAPI, Depends, Request, Response
from starlette.middleware.sessions import SessionMiddleware

from auth0_fastapi import Auth0Config, AuthClient
from auth0_fastapi.server.routes import router, register_auth_routes
from auth0_server_python.auth_types import DomainResolverContext

app = FastAPI(title="Multi-Domain App")
app.add_middleware(SessionMiddleware, secret_key=os.environ["SESSION_SECRET"])

# Domain configuration
DOMAIN_MAP = {
    "brand-1.yourapp.com": "login.brand-1.com",
    "brand-2.yourapp.com": "login.brand-2.com",
}
DEFAULT_DOMAIN = "login.yourapp.com"

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("x-forwarded-host") or \
           context.request_headers.get("host", "")
    host = host.split(":")[0]
    return DOMAIN_MAP.get(host, DEFAULT_DOMAIN)

config = Auth0Config(
    domain=domain_resolver,
    client_id=os.environ["AUTH0_CLIENT_ID"],
    client_secret=os.environ["AUTH0_CLIENT_SECRET"],
    app_base_url="https://yourapp.com",
    secret=os.environ["SESSION_SECRET"],
)

auth_client = AuthClient(config)
app.state.config = config
app.state.auth_client = auth_client

register_auth_routes(router, config)
app.include_router(router)

@app.get("/")
async def home():
    return {"message": "Multi-domain app"}

@app.get("/profile")
async def profile(session=Depends(auth_client.require_session)):
    return {"user": session.user}
```
