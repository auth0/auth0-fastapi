from typing import Any, Optional

from auth0_server_python.auth_types import StateData

#Imported from auth0-server-python
from auth0_server_python.store.abstract import StateStore
from fastapi import Response

from ..util import normalize_url


class StatefulStateStore(StateStore):
    """
    A state store implementation that persists session data in a backend store
    (for example, Redis or a database). It uses a cookie to keep track of the session ID.
    The underlying session store must implement asynchronous get, set, delete, and keys methods.
    """
    def __init__(self, secret: str, store: Any, cookie_name: str = "_a0_session", expiration: int = 259200):
        """
        :param secret: Secret for encryption (if needed)
        :param store: The persistent session store (e.g., a Redis client wrapper)
        :param cookie_name: Name of the cookie holding the session identifier
        :param expiration: Session expiration time in seconds
        """
        self.secret = secret
        self.store = store
        self.cookie_name = cookie_name
        self.expiration = expiration

    async def set(
        self,
        identifier: str,
        state: StateData,
        remove_if_exists: bool = False,
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Stores state data in the underlying session store and sets a cookie with the session ID.
        Expects 'response' in options.
        """
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options for stateful storage.")

        response: Response = options["response"]
        # Store the JSON representation. In a real implementation, encrypt if needed.
        data = state.model_dump_json()
        await self.store.set(identifier, data, expire=self.expiration)
        response.set_cookie(
            key=self.cookie_name,
            value=identifier,
            httponly=True,
            max_age=self.expiration,
        )

    async def get(
        self,
        identifier: str,
        options: Optional[dict[str, Any]] = None,
    ) -> Optional[StateData]:
        """
        Retrieves state data from the underlying session store using the session cookie.
        Expects 'request' in options.
        """
        if options is None or "request" not in options:
            raise ValueError("Request object is required in store options for stateful storage.")

        request = options["request"]
        session_id = request.cookies.get(self.cookie_name)
        if not session_id:
            return None

        data = await self.store.get(session_id)
        if not data:
            return None

        try:
            return StateData.model_validate(data)
        except Exception:
            return None

    async def delete(
        self,
        identifier: str,
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Deletes state data from the session store and clears the session cookie.
        Expects 'response' in options.
        """
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options for stateful storage.")

        response: Response = options["response"]
        await self.store.delete(identifier)
        response.delete_cookie(key=self.cookie_name)

    async def delete_by_logout_token(
        self,
        claims: dict[str, Any],
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Delete sessions matching the logout token claims.

        Per the OIDC Back-Channel Logout spec, either ``sid`` or ``sub``
        (or both) will be present.  Matching uses OR logic: a session
        is considered a match if either claim matches.

        When ``iss`` is present in claims, the token's issuer is validated
        against the session's stored domain before deletion.
        This prevents cross-domain session deletion in MCD deployments.
        """
        claim_sid = claims.get("sid")
        claim_sub = claims.get("sub")
        claim_iss = claims.get("iss")

        session_keys = await self.store.keys()
        for key in session_keys:
            data = await self.store.get(key)
            if not data:
                continue
            try:
                state = StateData.parse_raw(data)
                internal = state.internal.dict() if state.internal else {}
                user = state.user.dict() if state.user else {}

                # Validate issuer matches session domain (prevents cross-domain deletion in MCD)
                if claim_iss and state.domain:
                    if normalize_url(claim_iss) != normalize_url(state.domain):
                        continue

                # OR logic: match on sid OR sub
                matches_sid = claim_sid and internal.get("sid") == claim_sid
                matches_sub = claim_sub and user.get("sub") == claim_sub
                if matches_sid or matches_sub:
                    await self.store.delete(key)
            except Exception:
                continue
