from typing import Any, Optional, Union

from auth0_server_python.auth_types import StateData
from auth0_server_python.store.abstract import StateStore
from fastapi import Response


class StatelessStateStore(StateStore):
    """
    A stateless state store that encodes session data entirely in a cookie.
    The data is expected to be encrypted and tamper-proof.
    """
    def __init__(self, secret: str, cookie_name: str = "_a0_session", expiration: int = 259200):
        super().__init__({"secret": secret})
        self.cookie_name = cookie_name
        self.expiration = expiration
        self.max_cookie_size = 4096

        self.cookie_options = {
            "httponly": True,
            "samesite": "lax",
            "path": "/",
            "secure": True,
            "max_age": expiration,
        }

    async def set(
        self,
        identifier: str,
        state: Union[StateData, dict[str, Any]],
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Stores state data in an encrypted cookie.
        Expects 'response' in options.
        """
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options for stateless storage.")

        response: Response = options["response"]
        if hasattr(state, 'dict') and callable(state.dict):
            state_dict = state.dict()
        else:
            state_dict = state
        encrypted_data = self.encrypt(identifier, state_dict)
        chunk_size = self.max_cookie_size - len(self.cookie_name) - 10
        cookies = {}
        for i in range(0, len(encrypted_data), chunk_size):
            chunk_name = f"{self.cookie_name}_{i // chunk_size}"
            chunk_value = encrypted_data[i:i + chunk_size]
            cookies[chunk_name] = chunk_value
            response.set_cookie(
                key=chunk_name,
                value=chunk_value,
                path="/",
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age= self.expiration,
            )

    async def get(
        self,
        identifier: str,
        options: Optional[dict[str, Any]] = None,
    ) -> Optional[Union[StateData, dict[str, Any]]]:
        """
        Retrieves state data from the encrypted cookie.
        Expects 'request' in options.
        """
        if options is None or "request" not in options:
            raise ValueError("Request object is required in store options for stateless storage.")

        request = options["request"]

        session_parts = []
        for key, value in request.cookies.items():
            if key.startswith(self.cookie_name):
                index = int(key.split("_")[-1])
                session_parts.append((index, value))
        if not session_parts:
            return ""

        session_parts.sort()

        full_encoded_data = "".join(part[1] for part in session_parts)
        if not full_encoded_data:
            return None
        try:
            decrypted_data = self.decrypt(identifier, full_encoded_data)
            return decrypted_data
        except Exception:
            return None

    async def delete(
        self,
        identifier: str,
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Deletes the state cookie and its chunks.
        Expects 'response' in options.
        """
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options for stateless storage.")

        response: Response = options["response"]
        response.delete_cookie(key=self.cookie_name)

        for i in range(20):
            chunk_key = f"{self.cookie_name}_{i}"
            response.delete_cookie(key=chunk_key)
