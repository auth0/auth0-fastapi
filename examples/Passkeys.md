# Passkey Authentication

Passkeys let users sign up and log in with [WebAuthn](https://www.w3.org/TR/webauthn-2/) credentials (Touch ID, Face ID, Windows Hello, or a hardware security key) instead of a password. Signing in with a passkey stores the session in the same state store as `/auth/callback`. Request the `openid` scope and your `audience` when you sign in, as shown in [step 3](#step-3---sign-in-and-establish-the-session).

> **NOTE**: Passkeys require a [Custom Domain](https://auth0.com/docs/customize/custom-domains) and the native passkey feature on your tenant. See the [Auth0 passkey documentation](https://auth0.com/docs/authenticate/database-connections/passkeys).

`AuthClient` exposes three methods for this:

| Method | Used for | Session effect |
|---|---|---|
| `passkey_signup_challenge()` | Step 1 of signup | None |
| `passkey_login_challenge()` | Step 1 of login | None |
| `signin_with_passkey()` | Step 3 of signup and login | Establishes the session |

The methods are programmatic. The SDK does not mount passkey routes. You add the routes your front end calls, as shown below.

- [How the flow works](#how-the-flow-works)
- [Prerequisites](#prerequisites)
- [1. Passkey Signup](#1-passkey-signup)
- [2. Passkey Login](#2-passkey-login)
- [3. Identifier verification (optional)](#3-identifier-verification-optional)
- [4. Security considerations](#4-security-considerations)
- [5. Error Handling](#5-error-handling)
- [6. Organizations and DPoP (optional)](#6-organizations-and-dpop-optional)

## How the flow works

1. **Challenge** - your route calls `passkey_signup_challenge()` or `passkey_login_challenge()`. Auth0 returns an `auth_session` and the WebAuthn options (`authn_params_public_key`).
2. **Browser** - your front end passes the options to `navigator.credentials.create()` (signup) or `navigator.credentials.get()` (login).
3. **Sign in** - your route calls `signin_with_passkey()` with the `auth_session` and the credential. The SDK exchanges them for tokens and writes the session cookie.

## Prerequisites

- A Custom Domain on your tenant. WebAuthn binds the credential to that domain.
- Passkeys enabled on your database connection.
- The **Passkey** grant (`urn:okta:params:oauth:grant-type:webauthn`) enabled on your application.
- The SDK exception handler registered, so SDK errors become JSON responses:

```python
from auth0_fastapi.errors import register_exception_handlers

register_exception_handlers(app)
```

## 1. Passkey Signup

The routes below share these request models, constants and the `client_ip` helper. The models reject unknown fields and limit lengths before anything reaches Auth0. Read [Forward a trusted client IP](#4-security-considerations) before you deploy the helper.

```python
import ipaddress
from typing import Literal, Optional

from auth0_server_python.auth_types import PasskeyAuthResponse, PasskeyUserProfile
from auth0_server_python.error import MfaRequiredError
from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from auth0_fastapi.auth.auth_client import AuthClient
from auth0_fastapi.errors import PasskeyError

router = APIRouter()
CONNECTION = "Username-Password-Authentication"


class SignupChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=254)
    phone_number: Optional[str] = Field(None, min_length=4, max_length=30)
    delivery_method: Optional[Literal["text", "voice"]] = None


class VerificationCodes(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: Optional[str] = Field(None, max_length=10)
    phone: Optional[str] = Field(None, max_length=10)


class AssertionData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    clientDataJSON: str = Field(max_length=2048)
    attestationObject: Optional[str] = Field(None, max_length=4096)
    authenticatorData: Optional[str] = Field(None, max_length=2048)
    signature: Optional[str] = Field(None, max_length=2048)
    userHandle: Optional[str] = Field(None, max_length=2048)


class AuthnResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=1400)
    rawId: str = Field(max_length=1400)
    type: Literal["public-key"]
    authenticatorAttachment: Optional[str] = Field(None, max_length=30)
    response: AssertionData


class SigninRequest(BaseModel):
    auth_session: str = Field(min_length=1, max_length=256)
    authn_response: AuthnResponse
    verification: Optional[VerificationCodes] = None


def client_ip(request: Request) -> Optional[str]:
    host = request.client.host if request.client else None
    try:
        return str(ipaddress.ip_address(host)) if host else None
    except ValueError:
        return None
```

### Step 1 - Request a signup challenge

```python
@router.post("/passkey/signup/challenge")
async def passkey_signup_challenge(body: SignupChallengeRequest, request: Request, response: Response):
    auth_client: AuthClient = request.app.state.auth_client

    challenge = await auth_client.passkey_signup_challenge(
        user_profile=PasskeyUserProfile(email=body.email, phone_number=body.phone_number),
        connection=CONNECTION,
        delivery_method=body.delivery_method,
        client_ip=client_ip(request),
        store_options={"request": request, "response": response},
    )

    response.headers["Cache-Control"] = "no-store"
    return {
        "auth_session": challenge.auth_session,
        "public_key": challenge.authn_params_public_key.model_dump(by_alias=True, exclude_none=True),
        "verification_required": challenge.verification_required,
    }
```

`auth_session` is a short-lived session credential. The browser needs it for step 3. Keep it in a JavaScript variable only, not in `localStorage` or a URL. `auth_session` does not appear in `print(challenge)` or the model `repr()`.

### Step 2 - Create the credential in the browser

```javascript
function toAuthnResponse(credential) {
  const json = credential.toJSON();
  return {
    id: json.id,
    rawId: json.rawId,
    type: json.type,
    authenticatorAttachment: json.authenticatorAttachment,
    response: {
      clientDataJSON: json.response.clientDataJSON,
      attestationObject: json.response.attestationObject,
    },
  };
}

const challenge = await postJson("/passkey/signup/challenge", { email });

const credential = await navigator.credentials.create({
  publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(challenge.public_key),
});
const authnResponse = toAuthnResponse(credential);
```

`postJson` stands for your app's own `fetch` helper. Send only the `response` keys shown. The route rejects any other key and any value that is not a string, and drops a `null` optional value. If your target browsers lack `PublicKeyCredential.parseCreationOptionsFromJSON()`, base64url-decode `challenge` and `user.id` into `ArrayBuffer`s yourself.

### Step 3 - Sign in and establish the session

One route serves both signup and login.

```python
@router.post("/passkey/signin")
async def passkey_signin(body: SigninRequest, request: Request, response: Response):
    auth_client: AuthClient = request.app.state.auth_client
    codes = body.verification.model_dump(exclude_none=True) if body.verification else None

    try:
        result = await auth_client.signin_with_passkey(
            auth_session=body.auth_session,
            authn_response=PasskeyAuthResponse(**body.authn_response.model_dump(exclude_none=True)),
            verification=codes or None,
            connection=CONNECTION,
            scope="openid profile email offline_access",
            audience=auth_client.config.audience,
            client_ip=client_ip(request),
            store_options={"request": request, "response": response},
        )
    except PasskeyError as e:
        if not e.is_verification_retryable:
            raise
        response.status_code = 400
        response.headers["Cache-Control"] = "no-store"
        return {
            "error": "verification_retry",
            "auth_session": e.auth_session,
            "verification_required": e.verification_required,
        }
    except MfaRequiredError as e:
        response.status_code = 401
        response.headers["Cache-Control"] = "no-store"
        return {"error": "mfa_required", "mfa_token": e.mfa_token}

    user = result.state_data.get("user")
    return {"sub": user["sub"] if user else None}
```

`/auth/login` takes the `audience` and `authorization_params` from your `Auth0Config`, while `signin_with_passkey()` sends only the `scope` and `audience` you give it. Include `openid` in the scope, because Auth0 issues an ID token, and so the user in `state_data`, only with it. Use the same `audience` as your `Auth0Config`, so that `get_access_token()` finds the token this sign-in stored. Adjust `scope` to what your app needs, and drop `offline_access` if you do not want a refresh token.

`result` holds the user's access, refresh and ID tokens, and `repr(result)` prints them. Keep it on the server and never return or log it. The route above returns only the `sub`.

Return a dict, as shown, rather than building your own `JSONResponse`. The SDK writes the session cookie onto the injected `response`, and FastAPI copies it to the dict response. A new `JSONResponse` would drop it.

The `except PasskeyError` branch handles identifier verification and is covered in [section 3](#3-identifier-verification-optional). The `except MfaRequiredError` branch is for tenants that require MFA and is covered in [Completing MFA](#completing-mfa). Every other error is re-raised to the SDK exception handler.

## 2. Passkey Login

The login challenge takes no username, because the passkey the user picks identifies them.

```python
@router.post("/passkey/login/challenge")
async def passkey_login_challenge(request: Request, response: Response):
    auth_client: AuthClient = request.app.state.auth_client

    challenge = await auth_client.passkey_login_challenge(
        connection=CONNECTION,
        client_ip=client_ip(request),
        store_options={"request": request, "response": response},
    )

    response.headers["Cache-Control"] = "no-store"
    return {
        "auth_session": challenge.auth_session,
        "public_key": challenge.authn_params_public_key.model_dump(by_alias=True, exclude_none=True),
    }
```

In the browser, get the credential with `navigator.credentials.get()` and post it to the same `/passkey/signin` route as signup:

```javascript
function toLoginResponse(credential) {
  const json = credential.toJSON();
  const { clientDataJSON, authenticatorData, signature, userHandle } = json.response;
  return {
    id: json.id,
    rawId: json.rawId,
    type: json.type,
    authenticatorAttachment: json.authenticatorAttachment,
    response: { clientDataJSON, authenticatorData, signature, ...(userHandle ? { userHandle } : {}) },
  };
}

const challenge = await postJson("/passkey/login/challenge");

const credential = await navigator.credentials.get({
  publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(challenge.public_key),
});
await postJson("/passkey/signin", {
  auth_session: challenge.auth_session,
  authn_response: toLoginResponse(credential),
});
```

`userHandle` can be `null`. The helper leaves it out in that case, and the route drops a `null` value as well. Identifier verification does not apply to login.

## 3. Identifier verification (optional)

When your database connection requires users to verify their email or phone at signup, the signup challenge lists the identifiers that need a code in `verification_required` (for example `["email", "phone"]`). Auth0 sends one code per identifier, and you pass the codes to `signin_with_passkey()` in `verification`. Connections without verification follow section 1 unchanged.

### Requirements

Enable identifier verification for email, phone, or both on your database connection. For email, choose the One-Time Password (OTP) method, because this flow passes codes and does not support verification links.

- Configure an email provider for email codes and a phone provider for phone codes. Without one the code is never sent, so the user can't finish signing up.
- Deploy a version of your app that passes `verification` to `signin_with_passkey()` before you turn verification on. Otherwise every signup on the connection fails.
- For phone codes, `delivery_method` selects `"text"` or `"voice"`. It has no effect when only email needs a code. Any other value raises `InvalidArgumentError` before the request is sent.

### The flow

1. Request the signup challenge. If `verification_required` is set, prompt the user for a code for each identifier it lists.
2. Collect every code **before** calling `navigator.credentials.create()`, so a user who never receives a code doesn't end up with a passkey for an account that was never created. The SDK can't enforce this order. Auth0 checks the codes only in `signin_with_passkey()`, after the credential exists, so after a wrong code the passkey has no account behind it until a retry with that same credential succeeds.
3. Create the credential, then post it with the codes to `/passkey/signin`.

```javascript
async function signUpWithPasskey(email, phone_number) {
  const challenge = await postJson("/passkey/signup/challenge", { email, phone_number, delivery_method: "text" });

  let verification = challenge.verification_required
    ? await promptForCodes(challenge.verification_required)
    : undefined;

  const credential = await navigator.credentials.create({
    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(challenge.public_key),
  });
  const authnResponse = toAuthnResponse(credential);

  let authSession = challenge.auth_session;
  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await fetch("/passkey/signin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auth_session: authSession, authn_response: authnResponse, verification }),
    });
    if (res.ok) return res.json();

    const err = await res.json();
    if (err.error !== "verification_retry") throw err;
    authSession = err.auth_session;
    verification = await promptForCodes(err.verification_required);
  }
  throw new Error("Too many attempts. Start the signup again.");
}
```

`promptForCodes` stands for your app's UI that asks the user for a code per listed identifier and returns them keyed by `email` or `phone`. `toAuthnResponse` is defined in section 1, step 2.

### Handling a wrong code

After a wrong code the session stays valid. `signin_with_passkey()` raises a `PasskeyError` with `is_verification_retryable` set to `True`. Its `verification_required` lists the identifiers still unverified. The `/passkey/signin` route in section 1 returns these to the browser, and the browser resubmits:

- the `auth_session` from the error response
- the **same** credential (no second biometric prompt)
- codes only for the identifiers still listed

Cap the number of attempts in the browser, because Auth0 also limits them. Send one `/passkey/signin` request at a time per `auth_session`. Parallel requests can use up the allowed attempts.

### When retrying does not help

`is_verification_retryable` is `False` in these cases:

- **Too many wrong codes, an expired code, or an expired session** (`invalid_grant` without `auth_session`). Start again from the signup challenge.
- **A missing code** (`invalid_request`). The session stays valid. Resubmit with the same `auth_session` and a code for every identifier in `verification_required`.
- **A server error** (`server_error`). Retry with the same `auth_session`, credential and codes. If that fails with `invalid_grant` and no `auth_session`, start again.
- **A rate limit** (`status_code` is 429). Auth0 rejects the request before it uses the attempt. The exception handler returns HTTP 429, with a `Retry-After` header when Auth0 sent one. Wait that long, then resend the same request with the same `auth_session`, credential and codes. Check `status_code`, not `code`, because the code depends on which limit was hit.
- **Any other failure** is raised with the `error` code Auth0 returned, or `passkey_token_error` when the response has no JSON error body.

If the connection drops after Auth0 accepts the final code, or a Post Login Action denies the login, the account may already exist, because Auth0 creates the user before Actions run. A new signup with the same email then fails with `invalid_request`. Show a generic message that offers sign in, without confirming whether the account exists. `invalid_request` also covers invalid input, so don't treat it alone as proof that the account exists.

### Resending codes

To resend, call the signup challenge again before the credential is created. Each call sends new codes and returns a new `auth_session` and new WebAuthn options, so use the latest values.

## 4. Security considerations

- **Rate-limit the signup challenge route.** Each call sends codes, so without a limit the route can be abused to send messages in bulk (SMS pumping). Limit it per IP address and per email address or phone number, for example at your reverse proxy or with a library such as `slowapi`.
- **Forward a trusted client IP.** Pass `client_ip` to all three methods so Auth0 sees the user's address, not your server's. Auth0 uses it when the **Trust Token Endpoint IP Header** setting is enabled for the application, so a spoofed value lets a caller get around per-IP limits. How `request.client.host` is derived depends on your server. If you use uvicorn, it reads `X-Forwarded-For` only from the addresses in `--forwarded-allow-ips` (default `127.0.0.1`). Set that to the addresses of your own proxies and never to `*`, which makes uvicorn trust the first `X-Forwarded-For` entry, and the client can set that entry. With another server, check which forwarding headers it trusts and from whom. The value may not be a valid IP address (uvicorn passes the header through unchecked), so the `client_ip` helper returns the address only when it is valid and `None` otherwise, because Auth0 can reject any other value. Never copy a client-supplied header into `client_ip`.
- **Treat `auth_session` and verification codes as credentials.** Never log them, and never put them in URLs. Send `Cache-Control: no-store` on responses that carry `auth_session`. `PasskeyError` carries `auth_session` as an attribute, so do not log the error's attributes.
- **Validate at the route.** Use request models like the ones above: `extra="forbid"`, codes of at most 10 characters, and only the `email` and `phone` keys. The SDK also rejects any other `verification` key with `InvalidArgumentError`.
- **Keep retry details out of generic error responses.** `register_exception_handlers()` returns only `error` and `message`. Return `auth_session` only from the route that owns the retry, as in section 1.

## 5. Error Handling

With `register_exception_handlers(app)`, unhandled errors from the passkey methods map to these responses. The body is always `{"error": <code>, "message": <description>}`.

| Error | HTTP status |
|---|---|
| `PasskeyError` with `status_code` 429 (rate limited) | 429, with `Retry-After` when Auth0 sent one |
| Any other `PasskeyError` (for example `invalid_grant`, `invalid_request`, `passkey_challenge_error`, `passkey_token_error`) | 400 |
| `InvalidArgumentError` | 400 |
| `OrganizationTokenValidationError` | 400 |
| `MissingRequiredArgumentError` | 422 |
| `MfaRequiredError`, when the route does not catch it | 401 |
| `IssuerValidationError` | 401 |
| `ApiError` (ID token validation) | 502 |

### Completing MFA

When the tenant requires MFA after the passkey sign-in, `signin_with_passkey()` raises `MfaRequiredError` before any session exists. The sign-in route in section 1 catches it and returns the `mfa_token` with a 401, so the browser has something to continue with. Without that branch the exception handler returns a 401 with only `error` and `message`.

The browser sends the `mfa_token` back with the user's code. Treat the token as a credential: send `Cache-Control: no-store` and never log it. This route finishes the sign-in through the MFA client on the underlying `ServerClient` (`auth_client.client.mfa`). With `persist` set, `verify()` creates the session from the ID token in its response, so you do not store tokens yourself. Keep `openid` in the sign-in scope for that reason.

```python
class MfaVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mfa_token: str = Field(min_length=1, max_length=8192)
    otp: str = Field(min_length=1, max_length=12)


@router.post("/passkey/mfa/verify")
async def passkey_mfa_verify(body: MfaVerifyRequest, request: Request, response: Response):
    auth_client: AuthClient = request.app.state.auth_client

    await auth_client.client.mfa.verify(
        {"mfa_token": body.mfa_token, "otp": body.otp, "persist": True},
        store_options={"request": request, "response": response},
    )

    response.headers["Cache-Control"] = "no-store"
    return {"signed_in": True}
```

Some factors need a call to `mfa.challenge_authenticator()` before `verify()`, and recovery codes and out-of-band factors use other keys. See the [auth0-server-python MFA guide](https://github.com/auth0/auth0-server-python/blob/main/examples/MFA.md) for the options.

MFA on a passkey login needs the default cookie state store for now. `StatefulStateStore` cannot save the pending MFA state, so the sign-in fails with a generic error before `MfaRequiredError` reaches your route.

## 6. Organizations and DPoP (optional)

### Organizations

To sign users up and in within an organization, pass the same `organization` (ID or name) to the signup challenge, the login challenge and `signin_with_passkey()`. Your database connection must be enabled for the organization.

Define the organization next to `CONNECTION` and add it to the signup route:

```diff
 CONNECTION = "Username-Password-Authentication"
+ORGANIZATION = "org_abc123"
...
     challenge = await auth_client.passkey_signup_challenge(
         user_profile=PasskeyUserProfile(email=body.email, phone_number=body.phone_number),
         connection=CONNECTION,
+        organization=ORGANIZATION,
         delivery_method=body.delivery_method,
```

Add `organization=ORGANIZATION` to the login challenge and sign-in calls in the same way. The sign-in call matters most. With `organization` set, `signin_with_passkey()` checks the ID token and raises `OrganizationTokenValidationError` when the organization claim is missing or different, or when no ID token comes back. A signup that did not end up in the organization then fails instead of creating a session outside it. The exception handler returns 400 for that error.

### DPoP

Pass a `dpop_key` to `signin_with_passkey()` to get DPoP-bound tokens. The tokens work only with that key, so you need the same key for every later call that uses them.

```python
from jwcrypto import jwk

dpop_key = jwk.JWK.generate(kty="EC", crv="P-256")
```

Add `dpop_key=dpop_key` to the sign-in call in section 1. Then keep these points in mind:

- Generate one key per user session and keep it on the server, next to the session, in a store you control. Do not send it to the browser or put it in a cookie.
- The private key is a secret, so never log it. The [auth0-server-python passkey guide](https://github.com/auth0/auth0-server-python/blob/main/examples/Passkeys.md#3-dpop-bound-passkey-tokens-optional) covers key storage.
- If the tenant also requires MFA, pass the same key to `mfa.verify()` through its `dpop_key` argument. It raises only when you pass a key and the token comes back without a DPoP binding, so it does not notice a missing key.
- `get_access_token()` takes no `dpop_key`, so it sends no DPoP proof when it refreshes a token. Do not rely on it to refresh a session whose tokens are DPoP-bound.
- `signin_with_passkey()` raises a `PasskeyError` when the token type does not match whether you passed a key.

## Additional Resources

- [Auth0 passkey documentation](https://auth0.com/docs/authenticate/database-connections/passkeys)
- [auth0-server-python: Passkey Authentication](https://github.com/auth0/auth0-server-python/blob/main/examples/Passkeys.md)
- [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/)
