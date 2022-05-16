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

import pretend
import pytest
from requests import HTTPError

from sigstore._internal.oidc import ambient


def test_detect_credential_none(monkeypatch):
    detect_none = pretend.call_recorder(lambda: None)
    monkeypatch.setattr(ambient, "detect_github", detect_none)
    monkeypatch.setattr(ambient, "detect_gcp", detect_none)
    assert ambient.detect_credential() is None


def test_detect_credential(monkeypatch):
    detect_github = pretend.call_recorder(lambda: "fakejwt")
    monkeypatch.setattr(ambient, "detect_github", detect_github)

    assert ambient.detect_credential() == "fakejwt"


def test_detect_github_bad_env(monkeypatch):
    # We might actually be running in a CI, so explicitly remove this.
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    assert ambient.detect_github() is None
    assert logger.debug.calls == [
        pretend.call("GitHub: looking for OIDC credentials"),
        pretend.call("GitHub: environment doesn't look like a GH action; giving up"),
    ]


def test_detect_github_bad_permissions(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", raising=False)
    monkeypatch.delenv("ACTIONS_ID_TOKEN_REQUEST_URL", raising=False)

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match="GitHub: missing or insufficient OIDC token permissions?",
    ):
        ambient.detect_github()
    assert logger.debug.calls == [
        pretend.call("GitHub: looking for OIDC credentials"),
    ]


def test_detect_github_request_fails(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "faketoken")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "fakeurl")

    resp = pretend.stub(raise_for_status=pretend.raiser(HTTPError), status_code=999)
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: resp), HTTPError=HTTPError
    )
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GitHub: OIDC token request failed \(code=999\)",
    ):
        ambient.detect_github()
    assert requests.get.calls == [
        pretend.call(
            "fakeurl",
            params={"audience": "sigstore"},
            headers={"Authorization": "bearer faketoken"},
        )
    ]


def test_detect_github_bad_payload(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "faketoken")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "fakeurl")

    resp = pretend.stub(
        raise_for_status=lambda: None, json=pretend.call_recorder(lambda: {})
    )
    requests = pretend.stub(get=pretend.call_recorder(lambda url, **kw: resp))
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match="GitHub: malformed or incomplete JSON",
    ):
        ambient.detect_github()
    assert requests.get.calls == [
        pretend.call(
            "fakeurl",
            params={"audience": "sigstore"},
            headers={"Authorization": "bearer faketoken"},
        )
    ]
    assert resp.json.calls == [pretend.call()]


def test_detect_github(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "faketoken")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "fakeurl")

    resp = pretend.stub(
        raise_for_status=lambda: None,
        json=pretend.call_recorder(lambda: {"value": "fakejwt"}),
    )
    requests = pretend.stub(get=pretend.call_recorder(lambda url, **kw: resp))
    monkeypatch.setattr(ambient, "requests", requests)

    assert ambient.detect_github() == "fakejwt"
    assert requests.get.calls == [
        pretend.call(
            "fakeurl",
            params={"audience": "sigstore"},
            headers={"Authorization": "bearer faketoken"},
        )
    ]
    assert resp.json.calls == [pretend.call()]


def test_gcp_bad_env(monkeypatch):
    oserror = pretend.raiser(OSError)
    monkeypatch.setitem(ambient.__builtins__, "open", oserror)  # type: ignore

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    assert ambient.detect_gcp() is None
    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: environment doesn't have GCP product name file; giving up"),
    ]


def test_gcp_wrong_product(monkeypatch):
    stub_file = pretend.stub(
        __enter__=lambda *a: pretend.stub(read=lambda: "Unsupported Product"),
        __exit__=lambda *a: None,
    )
    monkeypatch.setitem(ambient.__builtins__, "open", lambda fn: stub_file)  # type: ignore

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match="GCP: product name file exists, but product name is 'Unsupported Product'; giving up",
    ):
        ambient.detect_gcp()

    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
    ]


def test_detect_gcp_request_fails(monkeypatch):
    stub_file = pretend.stub(
        __enter__=lambda *a: pretend.stub(read=lambda: "Google"),
        __exit__=lambda *a: None,
    )
    monkeypatch.setitem(ambient.__builtins__, "open", lambda fn: stub_file)  # type: ignore

    resp = pretend.stub(raise_for_status=pretend.raiser(HTTPError), status_code=999)
    requests = pretend.stub(
        get=pretend.call_recorder(lambda url, **kw: resp), HTTPError=HTTPError
    )
    monkeypatch.setattr(ambient, "requests", requests)

    with pytest.raises(
        ambient.AmbientCredentialError,
        match=r"GCP: OIDC token request failed \(code=999\)",
    ):
        ambient.detect_gcp()
    assert requests.get.calls == [
        pretend.call(
            ambient.GCP_ID_TOKEN_REQUEST_URL,
            params={"audience": "sigstore", "format": "full"},
            headers={"Metadata-Flavor": "Google"},
        )
    ]


@pytest.mark.parametrize("product_name", ("Google", "Google Compute Engine"))
def test_detect_gcp(monkeypatch, product_name):
    stub_file = pretend.stub(
        __enter__=lambda *a: pretend.stub(read=lambda: product_name),
        __exit__=lambda *a: None,
    )
    monkeypatch.setitem(ambient.__builtins__, "open", lambda fn: stub_file)  # type: ignore

    logger = pretend.stub(debug=pretend.call_recorder(lambda s: None))
    monkeypatch.setattr(ambient, "logger", logger)

    resp = pretend.stub(
        raise_for_status=lambda: None,
        text="fakejwt",
    )
    requests = pretend.stub(get=pretend.call_recorder(lambda url, **kw: resp))
    monkeypatch.setattr(ambient, "requests", requests)

    assert ambient.detect_gcp() == "fakejwt"
    assert requests.get.calls == [
        pretend.call(
            ambient.GCP_ID_TOKEN_REQUEST_URL,
            params={"audience": "sigstore", "format": "full"},
            headers={"Metadata-Flavor": "Google"},
        )
    ]
    assert logger.debug.calls == [
        pretend.call("GCP: looking for OIDC credentials"),
        pretend.call("GCP: requesting OIDC token"),
        pretend.call("GCP: successfully requested OIDC token"),
    ]
