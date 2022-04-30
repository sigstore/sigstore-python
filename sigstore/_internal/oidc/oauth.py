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

import base64
import hashlib
import http.server
import os
import threading
import time
import urllib.parse
import uuid
import webbrowser
from typing import Dict, cast

import requests

from sigstore._internal.oidc import IdentityError

AUTH_SUCCESS_HTML = """
<html>
<title>Sigstore Auth</title>
<body>
<h1>Sigstore Auth Successful</h1>
<p>You may now close this page.</p>
</body>
</html>
"""


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        server = cast(RedirectServer, self.server)
        r = urllib.parse.urlsplit(self.path)

        # Handle auth response
        if r.path == server.redirect_path:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            body = AUTH_SUCCESS_HTML.encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            server.auth_response = urllib.parse.parse_qs(r.query)
            return

        # Any other request generates an auth request
        url = server.auth_request()
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()


OOB_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"


class RedirectServer(http.server.HTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), RedirectHandler)
        self.state = None
        self.nonce = None
        self.auth_response = None
        self._port: int = self.socket.getsockname()[1]
        self.is_oob = False

    @property
    def active(self) -> bool:
        return self.auth_response is None

    @property
    def base_uri(self) -> str:
        return f"http://localhost:{self._port}"

    @property
    def redirect_path(self) -> str:
        return "/auth/callback"

    @property
    def redirect_uri(self) -> str:
        return (
            (self.base_uri + self.redirect_path)
            if not self.is_oob
            else OOB_REDIRECT_URI
        )

    def generate_code_challenge(self) -> bytes:
        self.code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=")
        return base64.urlsafe_b64encode(
            hashlib.sha256(self.code_verifier).digest()
        ).rstrip(b"=")

    def auth_request_params(self) -> Dict[str, str]:
        code_challenge = self.generate_code_challenge()
        self.state = str(uuid.uuid4())
        self.nonce = str(uuid.uuid4())
        return {
            "response_type": "code",
            "client_id": "sigstore",
            "scope": "openid email",
            "redirect_uri": self.redirect_uri,
            "code_challenge": code_challenge.decode("utf-8"),
            "code_challenge_method": "S256",
            "state": self.state,
            "nonce": self.nonce,
        }

    def auth_request(self) -> str:
        params = self.auth_request_params()
        return "https://oauth2.sigstore.dev/auth/auth?" + urllib.parse.urlencode(params)

    def enable_oob(self) -> None:
        self.is_oob = True


def get_identity_token() -> str:
    """
    Retrieve an OpenID Connect token from the Sigstore provider

    This function and the components that it relies on are based off of:
    https://github.com/psteniusubi/python-sample
    """

    code: str
    with RedirectServer() as server:
        # Launch web browser
        if webbrowser.open(server.base_uri):
            print(f"Your browser will now be opened to:\n{server.auth_request()}\n")
        else:
            server.enable_oob()
            print(
                f"Go to the following link in a browser:\n\n\t{server.auth_request()}"
            )

        thread = threading.Thread(
            target=lambda server: server.serve_forever(),
            args=(server,),
        )
        thread.start()

        if not server.is_oob:
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

        server.shutdown()
        thread.join()

    # Provide code to token endpoint
    data = {
        "grant_type": "authorization_code",
        "redirect_uri": server.redirect_uri,
        "code": code,
        "code_verifier": server.code_verifier.decode("utf-8"),
    }
    auth = (
        "sigstore",
        "",  # Client secret
    )
    resp: requests.Response = requests.post(
        "https://oauth2.sigstore.dev/auth/token",
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
