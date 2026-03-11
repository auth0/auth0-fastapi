# Multiple Custom Domains (MCD)

MCD lets you resolve the Auth0 domain per request while keeping a single `AuthClient` instance. This is useful when your application uses multiple custom domains configured on the same Auth0 tenant.

**Example:**
- `https://acme.yourapp.com` → Custom domain: `auth.acme.com`
- `https://globex.yourapp.com` → Custom domain: `auth.globex.com`

MCD is enabled by providing a **domain resolver function** instead of a static domain string.

## Basic Setup

### 1. Define a Domain Resolver

The domain resolver is an async function that receives request context and returns the appropriate Auth0 domain:

```python
from auth0_server_python.auth_types import DomainResolverContext

async def domain_resolver(context: DomainResolverContext) -> str:
    """
    Resolve Auth0 domain based on incoming request.

    Args:
        context.request_url: Full request URL (e.g., "https://tenant-a.myapp.com/auth/login")
        context.request_headers: Dict of request headers

    Returns:
        Auth0 domain string (e.g., "tenant-a.auth0.com")
    """
    if context.request_headers:
        host = context.request_headers.get("host", "").split(":")[0]

        # Map hostnames to Auth0 domains
        domain_map = {
            "tenant-a.myapp.com": "tenant-a.auth0.com",
            "tenant-b.myapp.com": "tenant-b.auth0.com",
        }
        return domain_map.get(host, "default.auth0.com")

    return "default.auth0.com"
```

### 2. Configure Auth0Config

Pass the resolver function instead of a static domain string:

```python
from auth0_fastapi import Auth0Config, AuthClient

config = Auth0Config(
    domain=domain_resolver,  # Callable triggers MCD mode
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET",
    app_base_url="https://myapp.com",
    secret="your-32-character-secret-key!!",
)

auth_client = AuthClient(config)
```

> **Note:** In resolver mode, the SDK builds the `redirect_uri` dynamically from the request host. You do not need to set it manually. If you override `redirect_uri` in `authorization_params`, the SDK uses your value as-is.

## Usage Patterns

### Pattern 1: Host Header Mapping

Map request hostnames directly to Auth0 domains:

```python
DOMAIN_MAP = {
    "acme.myapp.com": "acme-corp.auth0.com",
    "globex.myapp.com": "globex-inc.auth0.com",
    "initech.myapp.com": "initech.auth0.com",
}

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    return DOMAIN_MAP.get(host, "default.auth0.com")
```

### Pattern 2: Subdomain Extraction

> **Warning:** This pattern constructs the Auth0 domain from raw header input. An attacker who controls the `Host` header can influence the resolved domain. Use an allowlist (Pattern 1) for production deployments. See [Security Considerations](#use-an-allowlist-in-your-resolver).

Extract tenant from subdomain:

```python
async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]

    # Extract subdomain: "acme.myapp.com" -> "acme"
    parts = host.split(".")
    if len(parts) >= 3:
        tenant = parts[0]
        return f"{tenant}.auth0.com"

    return "default.auth0.com"
```

### Pattern 3: Database Lookup

Fetch domain from database based on tenant:

```python
async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]

    # Extract tenant identifier
    tenant = host.split(".")[0]

    # Lookup in database (use caching in production)
    tenant_config = await get_tenant_config(tenant)
    if tenant_config:
        return tenant_config.auth0_domain

    return "default.auth0.com"
```

### Pattern 4: Environment-Based Configuration

Use environment variables for tenant configuration:

```python
import os
import json

# Load from environment: TENANT_DOMAINS='{"acme": "acme.auth0.com", "globex": "globex.auth0.com"}'
TENANT_DOMAINS = json.loads(os.environ.get("TENANT_DOMAINS", "{}"))

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    tenant = host.split(".")[0]
    return TENANT_DOMAINS.get(tenant, os.environ.get("DEFAULT_AUTH0_DOMAIN"))
```

## Proxy Headers

When running behind a reverse proxy (nginx, load balancer), use forwarded headers:

```python
async def domain_resolver(context: DomainResolverContext) -> str:
    headers = context.request_headers or {}

    # Prefer x-forwarded-host over host
    host = headers.get("x-forwarded-host") or headers.get("host", "")
    host = host.split(":")[0]  # Remove port

    return DOMAIN_MAP.get(host, "default.auth0.com")
```

## Auth0 Dashboard Configuration

For MCD to work, configure your Auth0 application:

1. **Allowed Callback URLs**: Add all tenant callback URLs
   ```
   https://tenant-a.myapp.com/auth/callback
   https://tenant-b.myapp.com/auth/callback
   ```

2. **Allowed Logout URLs**: Add all tenant base URLs
   ```
   https://tenant-a.myapp.com
   https://tenant-b.myapp.com
   ```

3. **Allowed Web Origins** (if using SPA features):
   ```
   https://tenant-a.myapp.com
   https://tenant-b.myapp.com
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
        return "default.auth0.com"

        # Option 2: Raise error (will return 500 to user)
        # raise DomainResolverError(f"Unknown tenant: {host}")

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

In resolver mode, sessions are bound to the domain that created them. On each request, the SDK compares the session's stored domain against the current resolved domain:

- `get_user()` and `get_session()` return `None` on domain mismatch.
- `get_access_token()` raises `AccessTokenError` on domain mismatch.
- Token refresh uses the session's stored domain, not the current request domain.

> **Note:** When moving from a static domain to a resolver function, existing sessions that lack a `domain` field continue to work. The SDK uses a three-tier fallback to determine the session's domain: (1) `session.domain`, (2) the static domain if configured, (3) the hostname extracted from the user's `iss` claim. New sessions store the resolved domain automatically. See [Legacy Sessions](#legacy-sessions) for details.

## Legacy Sessions

When moving from a static domain setup to resolver mode, existing sessions can continue
to work if the resolver returns the same Auth0 domain that was used for those legacy sessions.

The SDK determines the session's domain using a fallback chain:

1. **`session.domain`** — new sessions created after MCD was enabled store this field.
2. **Static domain** — if a static `domain` string was configured, it is used as a fallback.
3. **User's issuer claim** — the hostname is extracted from the `iss` claim in the user's
   ID token (e.g., `https://tenant.auth0.com/` yields `tenant.auth0.com`).

In most cases, the issuer claim already matches the Auth0 domain, so legacy sessions work
without re-authentication. If the resolver returns a different domain that does not match
any fallback tier, the user will need to sign in again.

## Discovery Cache

The SDK caches OIDC metadata and JWKS per domain in memory (LRU eviction, 600-second TTL, up to 100 domains). This avoids repeated network calls when serving multiple domains. The cache is shared across all requests to the same `AuthClient` instance.

## Security Considerations

- **Session Isolation**: Sessions are bound to their origin domain. A session created on one custom domain cannot be used on another.
- **Issuer Validation**: Token issuer is validated against the expected domain (with normalization for trailing slashes and case)
- **Token Refresh**: Refresh tokens are used with their original domain's token endpoint
- **Redirect URI Protection**: Auth0 rejects authorization requests where `redirect_uri` is not in the application's Allowed Callback URLs, preventing redirect-based attacks even if host headers are spoofed.

### Use an Allowlist in Your Resolver

The SDK passes request headers to your domain resolver via `DomainResolverContext`. These headers come directly from the HTTP request and can be spoofed. Always use a mapping or allowlist — never construct domains from raw header values:

```python
# Safe: unknown hosts fall back to default
async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    return DOMAIN_MAP.get(host, DEFAULT_DOMAIN)

# Risky: attacker sends Host: evil.myapp.com → evil.auth0.com
async def domain_resolver(context: DomainResolverContext) -> str:
    tenant = context.request_headers.get("host", "").split(".")[0]
    return f"{tenant}.auth0.com"
```

### Trust Forwarded Headers Only Behind a Proxy

Only use `x-forwarded-host` when behind a trusted reverse proxy. Consider adding `TrustedHostMiddleware`:

```python
from starlette.middleware.trustedhost import TrustedHostMiddleware

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["acme.myapp.com", "globex.myapp.com"]
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

app = FastAPI(title="Multi-Tenant App")
app.add_middleware(SessionMiddleware, secret_key=os.environ["SESSION_SECRET"])

# Tenant configuration
TENANT_DOMAINS = {
    "acme.myapp.com": "acme-corp.auth0.com",
    "globex.myapp.com": "globex-inc.auth0.com",
}

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("x-forwarded-host") or \
           context.request_headers.get("host", "")
    host = host.split(":")[0]
    return TENANT_DOMAINS.get(host, "default.auth0.com")

config = Auth0Config(
    domain=domain_resolver,
    client_id=os.environ["AUTH0_CLIENT_ID"],
    client_secret=os.environ["AUTH0_CLIENT_SECRET"],
    app_base_url="https://myapp.com",
    secret=os.environ["SESSION_SECRET"],
)

auth_client = AuthClient(config)
app.state.config = config
app.state.auth_client = auth_client

register_auth_routes(router, config)
app.include_router(router)

@app.get("/")
async def home():
    return {"message": "Multi-tenant app"}

@app.get("/profile")
async def profile(session=Depends(auth_client.require_session)):
    return {"user": session.user}
```
