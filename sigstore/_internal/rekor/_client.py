"""
Client implementation for interacting with Rekor.
"""

import json
from abc import ABC
from typing import Optional
from urllib.parse import urljoin

import requests  # type: ignore

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev/api/v1/"


class Endpoint(ABC):
    def __init__(self, url: str, session: requests.Session):
        self.url = url
        self.session = session


class RekorClient:
    """The internal Rekor client"""

    def __init__(self, url: str = DEFAULT_REKOR_URL):
        self.url = url
        self.session = requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

    @property
    def index(self):
        return RekorIndex(urljoin(self.url, "index/"), session=self.session)

    @property
    def log(self):
        return RekorLog(urljoin(self.url, "log/"), session=self.session)


class RekorIndex(Endpoint):
    @property
    def retrieve(self):
        return RekorRetrieve(urljoin(self.url, "retrieve/"), session=self.session)


class RekorRetrieve(Endpoint):
    def post(self, sha256_hash: Optional[str] = None):
        data = {"hash": f"sha256:{sha256_hash}"}
        return self.session.post(self.url, data=data)


class RekorLog(Endpoint):
    @property
    def entries(self):
        return RekorEntries(urljoin(self.url, "entries/"), session=self.session)


class RekorEntries(Endpoint):
    def get(self, uuid: str):
        return self.session.get(urljoin(self.url, uuid)).json()

    def post(self, b64_artifact_signature: str, sha256_artifact_hash: str, encoded_public_key: str):
        data = {
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": b64_artifact_signature,
                    "publicKey": {"content": encoded_public_key},
                },
                "data": {"hash": {"algorithm": "sha256", "value": sha256_artifact_hash}},
            },
        }

        resp = self.session.post(self.url, data=json.dumps(data)).json()

        # Assumes we only get one entry back
        uuid, entry = list(resp.items())[0]

        return uuid, entry
