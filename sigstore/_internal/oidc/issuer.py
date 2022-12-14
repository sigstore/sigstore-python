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

"""
Helper that queries the OpenID configuration for a given issuer and extracts its endpoints.
"""

import urllib.parse

import requests


class IssuerError(Exception):
    """
    Raised on any communication or format error with an OIDC issuer.
    """

    pass


class Issuer:
    """
    Represents an OIDC issuer (IdP).
    """

    def __init__(self, base_url: str) -> None:
        """
        Create a new `Issuer` from the given base URL.

        This URL is used to locate an OpenID Connect configuration file,
        which is then used to bootstrap the issuer's state (such
        as authorization and token endpoints).
        """
        oidc_config_url = urllib.parse.urljoin(
            f"{base_url}/", ".well-known/openid-configuration"
        )

        resp: requests.Response = requests.get(oidc_config_url)
        try:
            resp.raise_for_status()
        except requests.HTTPError as http_error:
            raise IssuerError from http_error

        struct = resp.json()

        try:
            self.auth_endpoint: str = struct["authorization_endpoint"]
        except KeyError as key_error:
            raise IssuerError(
                f"OIDC configuration does not contain authorization endpoint: {struct}"
            ) from key_error

        try:
            self.token_endpoint: str = struct["token_endpoint"]
        except KeyError as key_error:
            raise IssuerError(
                f"OIDC configuration does not contain token endpoint: {struct}"
            ) from key_error
