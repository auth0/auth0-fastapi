from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse

from ..auth.auth_client import AuthClient
from ..config import Auth0Config
from ..util import create_route_url, to_safe_redirect

router = APIRouter()


def get_auth_client(request: Request) -> AuthClient:
    """
    Dependency function to retrieve the AuthClient instance.
    Assumes the client is set on the FastAPI application state.
    """
    auth_client = request.app.state.auth_client
    if not auth_client:
        raise HTTPException(
            status_code=500, detail="Authentication client not configured.")
    return auth_client


def register_auth_routes(router: APIRouter, config: Auth0Config):
    """
    Conditionally register auth routes based on config.mount_routes and config.mount_connect_routes.
    """
    if config.mount_routes:
        @router.get("/auth/login")
        async def login(
            request: Request,
            response: Response,
            auth_client: AuthClient = Depends(get_auth_client),
        ):
            """
            Endpoint to initiate the login process.
            Optionally accepts a 'return_to' query parameter and passes it as part of the app state.
            Redirects the user to the Auth0 authorization URL.
            """

            return_to: Optional[str] = request.query_params.get("returnTo")
            authorization_params = {k: v for k, v in request.query_params.items() if k not in [
                "returnTo"]}
            auth_url = await auth_client.start_login(
                app_state={"returnTo": return_to} if return_to else None,
                authorization_params=authorization_params,
                store_options={"response": response},
            )

            return RedirectResponse(url=auth_url, headers=response.headers)

        @router.get("/auth/callback")
        async def callback(
            request: Request,
            response: Response,
            auth_client: AuthClient = Depends(get_auth_client),
        ):
            """
            Endpoint to handle the callback after Auth0 authentication.
            Processes the callback URL and completes the login or connected account flow.
            Redirects the user to a post-login URL based on appState or a default.
            """
            full_callback_url = str(request.url)

            try:
                if "connect_code" in request.query_params.keys() and config.mount_connected_account_routes:
                    connect_complete_response = await auth_client.complete_connect_account(
                        full_callback_url, store_options={"request": request, "response": response})

                    app_state = connect_complete_response.app_state or {}
                else:
                    session_data = await auth_client.complete_login(
                        full_callback_url,store_options={"request": request, "response": response})

                    # Extract the returnTo URL from the appState if available.
                    app_state = session_data.get("app_state", {})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))


            # Extract the returnTo URL from the appState if available.
            return_to = app_state.get("returnTo")

            # Assuming config is stored on app.state
            default_redirect = auth_client.config.app_base_url

            return RedirectResponse(url=return_to or default_redirect, headers=response.headers)

        @router.get("/auth/logout")
        async def logout(
            request: Request,
            response: Response,
            auth_client: AuthClient = Depends(get_auth_client),
        ):
            """
            Endpoint to handle logout.
            Clears the session cookie (if applicable) and generates a logout URL,
            then redirects the user to Auth0's logout endpoint.
            """
            return_to: Optional[str] = request.query_params.get("returnTo")
            try:
                default_redirect = str(auth_client.config.app_base_url)
                logout_url = await auth_client.logout(
                    return_to=return_to or default_redirect,
                    store_options={"response": response},
                )
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

            return RedirectResponse(url=logout_url, headers=response.headers)

        @router.post("/auth/backchannel-logout")
        async def backchannel_logout(
            request: Request,
            auth_client: AuthClient = Depends(get_auth_client),
        ):
            """
            Endpoint to process backchannel logout notifications.
            Expects a JSON body with a 'logout_token'.
            Returns 204 No Content on success.
            """
            body = await request.json()
            logout_token = body.get("logout_token")
            if not logout_token:
                raise HTTPException(
                    status_code=400, detail="Missing 'logout_token' in request body.")

            try:
                await auth_client.handle_backchannel_logout(logout_token)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))
            return Response(status_code=204)

    if config.mount_connected_account_routes:
        @router.get("/auth/connect-account")
        async def connect_account(
            request: Request,
            response: Response,
            connection: str = Query(),
            auth_client: AuthClient = Depends(get_auth_client),
        ):
            """
            Endpoint to initiate the connect account flow for linking a third-party account to the user's profile.
            Redirects the user to the Auth0 connect account URL.
            """
            authorization_params = {k: v for k, v in request.query_params.items() if k not in [
                "connection", "returnTo"]}

            return_to = request.query_params.get("returnTo")
            connect_account_url = await auth_client.start_connect_account(
                connection=connection,
                app_state={"returnTo": return_to} if return_to else None,
                authorization_params=authorization_params,
                store_options={"request": request, "response": response},
            )

            return RedirectResponse(url=connect_account_url, headers=response.headers)

    if config.mount_connect_routes:

        @router.get("/auth/connect")
        async def connect(
            request: Request, response: Response,
            connection: Optional[str] = Query(None),
            connectionScope: Optional[str] = Query(None),
            returnTo: Optional[str] = Query(None),
            auth_client: AuthClient = Depends(get_auth_client),
        ):

            # Extract query parameters (connection, connectionScope, returnTo)
            connection = connection or request.query_params.get("connection")
            connection_scope = connectionScope or request.query_params.get(
                "connectionScope")
            dangerous_return_to = returnTo or request.query_params.get(
                "returnTo")

            if not connection:
                raise HTTPException(
                    status_code=400,
                    detail="connection is not set",
                )

            sanitized_return_to = to_safe_redirect(
                dangerous_return_to or "/", auth_client.config.app_base_url)

            # Create the callback URL for linking
            callback_path = "/auth/connect/callback"
            redirect_uri = create_route_url(
                callback_path, auth_client.config.app_base_url)

            # Call the startLinkUser method on our AuthClient. This method should accept parameters similar to:
            # connection, connectionScope, authorizationParams (with redirect_uri), and app_state.
            link_user_url = await auth_client.start_link_user({
                "connection": connection,
                "connectionScope": connection_scope,
                "authorization_params": {
                    "redirect_uri": str(redirect_uri),
                },
                "app_state": {
                    "returnTo": sanitized_return_to,
                },
            }, store_options={"request": request, "response": response})

            return RedirectResponse(url=link_user_url, headers=response.headers)

        @router.get("/auth/connect/callback")
        async def connect_callback(
            request: Request,
            response: Response,
            auth_client: AuthClient = Depends(get_auth_client),
        ):
            # Use the full URL from the callback
            callback_url = str(request.url)
            try:
                result = await auth_client.complete_link_user(
                    callback_url,
                    store_options={"request": request, "response": response},
                )
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

            # Retrieve the returnTo parameter from app_state if available
            return_to = result.get("app_state", {}).get("returnTo")

            app_base_url = auth_client.config.app_base_url

            return RedirectResponse(url=return_to or app_base_url, headers=response.headers)

        @router.get("/auth/unconnect")
        async def unconnect(
            request: Request,
            response: Response,
            connection: Optional[str] = Query(None),
            connectionScope: Optional[str] = Query(None),
            returnTo: Optional[str] = Query(None),
            auth_client: AuthClient = Depends(get_auth_client),
        ):

            # Extract query parameters (connection, connectionScope, returnTo)
            connection = connection or request.query_params.get("connection")
            dangerous_return_to = returnTo or request.query_params.get(
                "returnTo")

            if not connection:
                raise HTTPException(
                    status_code=400,
                    detail="connection is not set",
                )

            sanitized_return_to = to_safe_redirect(
                dangerous_return_to or "/", auth_client.config.app_base_url)

            # Create the callback URL for linking
            callback_path = "/auth/unconnect/callback"
            redirect_uri = create_route_url(
                callback_path, auth_client.config.app_base_url)

            # Call the startLinkUser method on our AuthClient. This method should accept parameters similar to:
            # connection, connectionScope, authorizationParams (with redirect_uri), and app_state.
            link_user_url = await auth_client.start_unlink_user({
                "connection": connection,
                "authorization_params": {
                    "redirect_uri": str(redirect_uri),
                },
                "app_state": {
                    "returnTo": sanitized_return_to,
                },
            }, store_options={"request": request, "response": response})

            return RedirectResponse(url=link_user_url, headers=response.headers)

        @router.get("/auth/unconnect/callback")
        async def unconnect_callback(
            request: Request,
            response: Response,
            auth_client: AuthClient = Depends(get_auth_client),
        ):
            # Use the full URL from the callback
            callback_url = str(request.url)
            try:
                result = await auth_client.complete_unlink_user(
                    callback_url,
                    store_options={"request": request, "response": response},
                )
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

            # Retrieve the returnTo parameter from appState if available
            return_to = result.get("app_state", {}).get("returnTo")

            app_base_url = auth_client.config.app_base_url

            return RedirectResponse(url=return_to or app_base_url, headers=response.headers)
