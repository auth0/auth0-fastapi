# Multiple Custom Domains (MCD)

This guide covers usage patterns for implementing Multiple Custom Domains in your FastAPI application.

## Overview

MCD allows a single application to serve multiple tenants, each with their own Auth0 domain. This is useful for:

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

For MCD to work, configure each Auth0 tenant:

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
from auth0_server_python.errors import DomainResolverError

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

1. **Login**: Resolves domain from request, builds dynamic `redirect_uri`, stores `origin_domain` in transaction
2. **Callback**: Retrieves `origin_domain` from transaction, exchanges code with correct token endpoint, validates issuer
3. **Session**: Stores `domain` field in session for future requests
4. **Token Refresh**: Uses session's stored domain (not current request domain)
5. **Logout**: Resolves current domain for logout URL

## Security Considerations

- **Session Isolation**: Sessions are bound to their origin domain. A session created on `tenant-a.myapp.com` cannot be used on `tenant-b.myapp.com`
- **Issuer Validation**: Token issuer is validated against the expected domain (with normalization for trailing slashes and case)
- **Token Refresh**: Refresh tokens are used with their original domain's token endpoint

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
