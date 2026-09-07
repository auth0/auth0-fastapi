
from typing import Optional

from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import (
    CompleteConnectAccountResponse,
    ConnectAccountOptions,
    CustomTokenExchangeOptions,
    LoginWithCustomTokenExchangeOptions,
    LoginWithCustomTokenExchangeResult,
    LogoutOptions,
    SessionTransferTokenResult,
    StartInteractiveLoginOptions,
    TokenExchangeResponse,
)
from fastapi import HTTPException, Request, Response, status

from auth0_fastapi.config import Auth0Config
from auth0_fastapi.stores.cookie_transaction_store import CookieTransactionStore
from auth0_fastapi.stores.stateless_state_store import StatelessStateStore


class AuthClient:
    """FastAPI wrapper for auth0-server-python authentication flows."""

    def __init__(
        self,
        config: Auth0Config,
        state_store=None,
        transaction_store=None,
    ):
        self.config = config
        redirect_uri = f"{str(config.app_base_url).rstrip('/')}/auth/callback"

        if state_store is None:
            state_store = StatelessStateStore(
                config.secret, cookie_name="_a0_session", expiration=config.session_expiration)
        if transaction_store is None:
            transaction_store = CookieTransactionStore(
                config.secret, cookie_name="_a0_tx")

        # MCD resolves the domain per-request, so redirect_uri cannot be set here
        auth_params = {
            "audience": config.audience,
            **(config.authorization_params or {}),
        }
        if not callable(config.domain):
            auth_params["redirect_uri"] = redirect_uri

        self.client = ServerClient(
            domain=config.domain,
            client_id=config.client_id,
            client_secret=config.client_secret,
            redirect_uri=redirect_uri,
            secret=config.secret,
            transaction_store=transaction_store,
            state_store=state_store,
            pushed_authorization_requests=config.pushed_authorization_requests,
            authorization_params=auth_params,
        )

    async def start_login(
        self,
        app_state: dict = None,
        authorization_params: dict = None,
        store_options: dict = None,
    ) -> str:
        """Initiates the interactive login flow and returns the authorization URL."""
        pushed_authorization_requests = self.config.pushed_authorization_requests
        options = StartInteractiveLoginOptions(
            pushed_authorization_requests=pushed_authorization_requests,
            app_state=app_state,
            authorization_params=authorization_params if not pushed_authorization_requests else None,
        )
        return await self.client.start_interactive_login(options, store_options=store_options)

    async def complete_login(
        self,
        callback_url: str,
        store_options: dict = None,
    ) -> dict:
        """Completes the login callback and returns the session state."""
        return await self.client.complete_interactive_login(callback_url, store_options=store_options)

    async def start_connect_account(
        self,
        connection: str,
        scopes: Optional[list[str]] = None,
        app_state: dict = None,
        authorization_params: dict = None,
        store_options: dict = None,
    ) -> str:
        """Initiates the connected account flow and returns the redirect URL."""
        options = ConnectAccountOptions(
            connection=connection,
            scopes=scopes,
            app_state=app_state,
            authorization_params=authorization_params
        )
        return await self.client.start_connect_account(options=options, store_options=store_options)

    async def complete_connect_account(
        self,
        url: str,
        store_options: dict = None,
    ) -> CompleteConnectAccountResponse:
        """Completes the connect account callback and returns the response."""
        return await self.client.complete_connect_account(url, store_options=store_options)

    async def logout(
        self,
        return_to: str = None,
        store_options: dict = None,
    ) -> str:
        """Initiates logout and returns the Auth0 logout URL."""
        options = LogoutOptions(return_to=return_to)
        return await self.client.logout(options, store_options=store_options)

    async def handle_backchannel_logout(
        self,
        logout_token: str,
        store_options: dict = None,
    ) -> None:
        """Processes a backchannel logout notification."""
        return await self.client.handle_backchannel_logout(logout_token, store_options=store_options)

    async def start_link_user(
        self,
        options: dict,
        store_options: dict = None,
    ) -> str:
        """Initiates the user linking flow and returns the redirect URL."""
        return await self.client.start_link_user(options, store_options=store_options)

    async def complete_link_user(
        self,
        url: str,
        store_options: dict = None,
    ) -> dict:
        """Completes the user linking callback and returns the app state."""
        return await self.client.complete_link_user(url, store_options=store_options)

    async def start_unlink_user(
        self,
        options: dict,
        store_options: dict = None,
    ) -> str:
        """Initiates the user unlinking flow and returns the redirect URL."""
        return await self.client.start_unlink_user(options, store_options=store_options)

    async def complete_unlink_user(
        self,
        url: str,
        store_options: dict = None,
    ) -> dict:
        """Completes the user unlinking callback and returns the app state."""
        return await self.client.complete_unlink_user(url, store_options=store_options)

    async def require_session(
        self,
        request: Request,
        response: Response,
    ) -> dict:
        """FastAPI dependency that returns the current session or raises HTTP 401."""
        store_options = {"request": request, "response": response}
        session = await self.client.get_session(store_options=store_options)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Please log in")
        return session

    async def custom_token_exchange(
        self,
        options: CustomTokenExchangeOptions,
        store_options: dict = None,
    ) -> TokenExchangeResponse:
        """
        Exchanges a subject token for Auth0 tokens via RFC 8693 without creating a session.

        Args:
            options: Exchange configuration.
            store_options: Store options. Required for Multiple Custom Domain domain resolution.

        Returns:
            TokenExchangeResponse.

        Raises:
            CustomTokenExchangeError: If the exchange fails.
        """
        return await self.client.custom_token_exchange(options, store_options=store_options)

    async def login_with_custom_token_exchange(
        self,
        options: LoginWithCustomTokenExchangeOptions,
        store_options: dict = None,
    ) -> LoginWithCustomTokenExchangeResult:
        """
        Exchanges a subject token for Auth0 tokens via RFC 8693 and establishes a session.

        Args:
            options: Exchange configuration.
            store_options: Must include request and response to write the session cookie.

        Returns:
            LoginWithCustomTokenExchangeResult.

        Raises:
            CustomTokenExchangeError: If the exchange fails.
            ValueError: If store_options is missing the response.
        """
        return await self.client.login_with_custom_token_exchange(options, store_options=store_options)

    async def request_session_transfer_token(
        self,
        subject_token: str,
        subject_token_type: str,
        actor_token: Optional[str] = None,
        actor_token_type: Optional[str] = None,
        scope: Optional[str] = None,
        organization: Optional[str] = None,
        store_options: dict = None,
    ) -> SessionTransferTokenResult:
        """
        Requests a Session Transfer Token (STT) for impersonation via session transfer.

        The returned STT is opaque and single-use - pass it directly to
        build_session_transfer_redirect and do not decode or store it.

        Args:
            subject_token: Proof of which customer to impersonate (validated by your CTE Action).
            subject_token_type: Token type URI routing to your CTE Profile.
            actor_token: The acting party's token. Defaults to the agent session's ID token.
            actor_token_type: Type URI of the actor token. Defaults to the ID token URN.
            scope: Space-delimited scopes (optional).
            organization: Organization identifier (optional).
            store_options: Must include request and response to read the agent session.

        Returns:
            SessionTransferTokenResult containing the STT and its metadata.

        Raises:
            CustomTokenExchangeError: If no actor can be resolved or the exchange fails.
            InvalidArgumentError: If organization is provided but blank.
        """
        return await self.client.request_session_transfer_token(
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            actor_token=actor_token,
            actor_token_type=actor_token_type,
            scope=scope,
            organization=organization,
            store_options=store_options,
        )

    def build_session_transfer_redirect(
        self,
        target_login_url: str,
        result: SessionTransferTokenResult,
        organization: Optional[str] = None,
    ) -> str:
        """
        Builds the redirect URL that hands the STT to the target app's login URL.

        target_login_url must be a trusted, app-controlled absolute https URL
        (http is allowed only for localhost/loopback) - the STT is a single-use
        credential and must not leak to an untrusted host.

        Args:
            target_login_url: The target app's login URL (absolute, https).
            result: The SessionTransferTokenResult from request_session_transfer_token.
            organization: Organization identifier to forward (optional).

        Returns:
            URL string with session_transfer_token (and organization) as query parameters.

        Raises:
            MissingRequiredArgumentError: If target_login_url is missing or blank.
            InvalidArgumentError: If target_login_url is not an absolute https URL,
                or organization is blank.
        """
        return self.client.build_session_transfer_redirect(
            target_login_url=target_login_url,
            result=result,
            organization=organization,
        )
