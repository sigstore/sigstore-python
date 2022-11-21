# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import base64
import hashlib
import http.server
import logging
import os
import threading
import time
import urllib.parse
import uuid
import webbrowser
from typing import Any, Dict, List, Optional, cast

import requests

from sigstore._internal.oidc import IdentityError
from sigstore._internal.oidc.issuer import Issuer

logger = logging.getLogger(__name__)

DEFAULT_OAUTH_ISSUER = "https://oauth2.sigstore.dev/auth"
STAGING_OAUTH_ISSUER = "https://oauth2.sigstage.dev/auth"


AUTH_SUCCESS_HTML = """
<html>
<title>Sigstore Auth</title>
<body>
<h1>Sigstore Auth Successful</h1>
<p>You may now close this page.</p>
</body>
</html>
"""


class OAuthFlow:
    def __init__(self, client_id: str, client_secret: str, issuer: Issuer):
        self._client_id = client_id
        self._client_secret = client_secret
        self._issuer = issuer
        self._server = OAuthRedirectServer(
            self._client_id, self._client_secret, self._issuer
        )
        self._server_thread = threading.Thread(
            target=lambda server: server.serve_forever(),
            args=(self._server,),
        )

    def __enter__(self) -> OAuthRedirectServer:
        self._server_thread.start()

        return self._server

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self._server.shutdown()
        self._server_thread.join()


class OAuthRedirectHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: Any) -> None:
        pass

    def do_GET(self) -> None:
        logger.debug(f"GET: {self.path} with {dict(self.headers)}")
        server = cast(OAuthRedirectServer, self.server)

        # If the auth response has already been populated, the main thread will be stopping this
        # thread and accessing the auth response shortly so we should stop servicing any requests.
        if server.auth_response is not None:
            logger.debug(f"{self.path} unavailable (teardown)")
            self.send_response(404)
            return None

        r = urllib.parse.urlsplit(self.path)

        # We only understand two kinds of requests:
        # 1. The response from a successful OAuth redirect
        # 2. The initial request to /, which kicks off (1)
        if r.path == server.redirect_path:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            body = AUTH_SUCCESS_HTML.encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            server.auth_response = urllib.parse.parse_qs(r.query)
        elif r.path == server.auth_request_path:
            self.send_response(302)
            self.send_header("Location", server.auth_endpoint)
            self.end_headers()
        else:
            # Anything else sends a "Not Found" response.
            self.send_response(404)


OOB_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"


class OAuthSession:
    def __init__(self, client_id: str, client_secret: str, issuer: Issuer):
        self.__poison = False

        self._client_id = client_id
        self._client_secret = client_secret
        self._issuer = issuer
        self._state = str(uuid.uuid4())
        self._nonce = str(uuid.uuid4())

        self.code_verifier = (
            base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        )

    @property
    def code_challenge(self) -> str:
        return (
            base64.urlsafe_b64encode(
                hashlib.sha256(self.code_verifier.encode()).digest()
            )
            .rstrip(b"=")
            .decode()
        )

    def auth_endpoint(self, redirect_uri: str) -> str:
        # Defensive programming: we don't have a nice way to limit the
        # lifetime of the OAuth session here, so we use the internal
        # "poison" flag to check if we're attempting to reuse it in a way
        # that would compromise the flow's security (i.e. nonce reuse).
        if self.__poison:
            raise IdentityError("internal error: OAuth endpoint misuse")
        else:
            self.__poison = True

        params = self._auth_params(redirect_uri)
        return f"{self._issuer.auth_endpoint}?{urllib.parse.urlencode(params)}"

    def _auth_params(self, redirect_uri: str) -> Dict[str, Any]:
        return {
            "response_type": "code",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": "openid email",
            "redirect_uri": redirect_uri,
            "code_challenge": self.code_challenge,
            "code_challenge_method": "S256",
            "state": self._state,
            "nonce": self._nonce,
        }


class OAuthRedirectServer(http.server.HTTPServer):
    def __init__(self, client_id: str, client_secret: str, issuer: Issuer) -> None:
        super().__init__(("localhost", 0), OAuthRedirectHandler)
        self.oauth_session = OAuthSession(client_id, client_secret, issuer)
        self.auth_response: Optional[Dict[str, List[str]]] = None
        self._is_out_of_band = False

    @property
    def base_uri(self) -> str:
        # NOTE: We'd ideally use `self.server_name` here, but it uses
        # the FQDN internally (which in turn confuses Sigstore).
        return f"http://localhost:{self.server_port}"

    @property
    def auth_request_path(self) -> str:
        # TODO: Maybe this should be /auth, for clarity?
        return "/"

    @property
    def redirect_path(self) -> str:
        return "/auth/callback"

    @property
    def redirect_uri(self) -> str:
        return (
            (self.base_uri + self.redirect_path)
            if not self._is_out_of_band
            else OOB_REDIRECT_URI
        )

    @property
    def auth_endpoint(self) -> str:
        return self.oauth_session.auth_endpoint(self.redirect_uri)

    def enable_oob(self) -> None:
        logger.debug("enabling out-of-band OAuth flow")
        self._is_out_of_band = True

    def is_oob(self) -> bool:
        return self._is_out_of_band


def get_identity_token(client_id: str, client_secret: str, issuer: Issuer) -> str:
    """
    Retrieve an OpenID Connect token from the Sigstore provider

    This function and the components that it relies on are based off of:
    https://github.com/psteniusubi/python-sample
    """

    force_oob = os.getenv("SIGSTORE_OAUTH_FORCE_OOB") is not None

    code: str
    with OAuthFlow(client_id, client_secret, issuer) as server:
        # Launch web browser
        if not force_oob and webbrowser.open(server.base_uri):
            print("Waiting for browser interaction...")
        else:
            server.enable_oob()
            print(f"Go to the following link in a browser:\n\n\t{server.auth_endpoint}")

        if not server.is_oob():
            # Wait until the redirect server populates the response
            while server.auth_response is None:
                time.sleep(0.1)

            auth_error = server.auth_response.get("error")
            if auth_error is not None:
                raise IdentityError(
                    f"Error response from auth endpoint: {auth_error[0]}"
                )
            code = server.auth_response["code"][0]
        else:
            # In the out-of-band case, we wait until the user provides the code
            code = input("Enter verification code: ")

    # Provide code to token endpoint
    data = {
        "grant_type": "authorization_code",
        "redirect_uri": server.redirect_uri,
        "code": code,
        "code_verifier": server.oauth_session.code_verifier,
    }
    auth = (
        client_id,
        client_secret,
    )
    logging.debug(f"PAYLOAD: data={data}")
    resp: requests.Response = requests.post(
        issuer.token_endpoint,
        data=data,
        auth=auth,
    )

    try:
        resp.raise_for_status()
    except requests.HTTPError as http_error:
        raise IdentityError from http_error

    token_json = resp.json()
    token_error = token_json.get("error")
    if token_error is not None:
        raise IdentityError(f"Error response from token endpoint: {token_error}")

    return str(token_json["access_token"])
