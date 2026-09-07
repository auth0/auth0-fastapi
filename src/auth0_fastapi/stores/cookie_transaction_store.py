from typing import Any, Optional

from auth0_server_python.auth_types import TransactionData
from auth0_server_python.store.abstract import TransactionStore
from fastapi import Request, Response


class CookieTransactionStore(TransactionStore):
    """Cookie-backed transaction store. Requires request and response in store_options."""
    def __init__(self, secret: str, cookie_name: str = "_a0_tx"):
        super().__init__({"secret": secret})
        self.cookie_name = cookie_name

    async def set(
        self,
        identifier: str,
        value: TransactionData,
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Encrypts and stores the transaction data in a cookie.
        Expects 'response' in options.
        """
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options for cookie storage.")

        response: Response = options["response"]

        encrypted_value = self.encrypt(identifier, value.model_dump())
        response.set_cookie(
            key=self.cookie_name,
            value=encrypted_value,
            path="/",samesite="Lax",
            secure=True, httponly=True,
            max_age=60,
        )

    async def get(
        self,
        identifier: str,
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Retrieves and parses the transaction data from the cookie.
        Expects 'request' in options.
        """
        if options is None or "request" not in options:
            raise ValueError("Request object is required in store options for cookie storage.")

        request: Request = options["request"]
        encrypted_value = request.cookies.get(self.cookie_name)
        if not encrypted_value:
            return None

        try:
            decrypted_data = self.decrypt(identifier, encrypted_value)
            return TransactionData.model_validate(decrypted_data)
        except Exception:
            return None

    async def delete(
        self,
        identifier: str,
        options: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Deletes the transaction cookie.
        Expects 'response' in options.
        """
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options for cookie storage.")

        response: Response = options["response"]
        response.delete_cookie(key=self.cookie_name)
