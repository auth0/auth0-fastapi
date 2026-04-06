from typing import TYPE_CHECKING, Optional
from urllib.parse import urljoin, urlparse

if TYPE_CHECKING:
    from fastapi import Request


def ensure_no_leading_slash(url: str) -> str:
    """
    Removes any leading slash from the given URL string.
    """
    return url.lstrip('/')


def ensure_trailing_slash(base: str) -> str:
    """
    Ensures that the base URL ends with a slash.
    """
    base_str = str(base)
    return base_str if base_str.endswith('/') else base_str + '/'


def create_route_url(url: str, base: str) -> str:
    """
    Ensures route URLs are created correctly by removing the leading slash from the
    provided URL and ensuring the base URL has a trailing slash. Then uses urljoin
    to combine them.

    Args:
        url: The URL (or path) to use.
        base: The base URL to use.

    Returns:
        A complete URL string combining the base and url.
    """
    base_fixed = ensure_trailing_slash(base)
    url_fixed = ensure_no_leading_slash(url)
    return urljoin(base_fixed, url_fixed)


def to_safe_redirect(dangerous_redirect: str, safe_base_url: str) -> Optional[str]:
    """
    Ensures that the redirect URL is safe to use by verifying that its origin matches
    the origin of the safe_base_url.

    Args:
        dangerous_redirect: The redirect URL to check.
        safe_base_url: The base URL to check against.

    Returns:
        A safe redirect URL string if the origins match, or None otherwise.
    """
    try:
        # Ensure safe_base_url is a string.
        safe_base_url_str = str(safe_base_url)
        route_url = create_route_url(dangerous_redirect, safe_base_url_str)
    except Exception:
        return None

    # Build origins from string values
    safe_origin = urlparse(safe_base_url_str).scheme + \
        "://" + urlparse(safe_base_url_str).netloc
    route_origin = urlparse(route_url).scheme + "://" + \
        urlparse(route_url).netloc

    if route_origin == safe_origin:
        return route_url
    return None


def normalize_url(value: str) -> str:
    """
    Normalize a URL or domain string for comparison.

    Returns:
        Normalized ``https://<host>`` string, or empty string if input
        is empty.
    """
    if not value:
        return ""

    value = value.strip()

    # Ensure a scheme is present so urlparse can extract the host
    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)

    # Lowercase scheme and host
    scheme = (parsed.scheme or "https").lower()
    if scheme == "http":
        scheme = "https"

    host = (parsed.hostname or "").lower()
    if not host:
        return ""

    # Remove default port
    port = parsed.port
    if port and ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        port = None

    netloc = f"{host}:{port}" if port else host

    return f"{scheme}://{netloc}"


def build_request_base_url(request: "Request") -> str:
    """
    Build base URL from request headers.
    Supports proxy headers (x-forwarded-host, x-forwarded-proto) for MCD scenarios.

    Args:
        request: FastAPI Request object

    Returns:
        Base URL string (e.g., "https://app.example.com")
    """
    host = request.headers.get('x-forwarded-host') or request.headers.get('host', 'localhost')
    proto = request.headers.get('x-forwarded-proto', 'http')

    # Remove port from host if it's standard (443 for https, 80 for http)
    if host.endswith(':443') and proto == 'https':
        host = host[:-4]
    elif host.endswith(':80') and proto == 'http':
        host = host[:-3]

    return f"{proto}://{host}"
