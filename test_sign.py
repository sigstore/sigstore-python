#!/usr/bin/env python

import logging

from in_toto_attestation.v1.resource_descriptor import ResourceDescriptor
from in_toto_attestation.v1.statement import Statement

from sigstore.oidc import Issuer
from sigstore.sign import SigningContext

logging.getLogger().setLevel(logging.DEBUG)

ctx = SigningContext.staging()
with ctx.signer(identity_token=Issuer.staging().identity_token()) as signer:
    stmt = Statement(
        subjects=[
            ResourceDescriptor(
                name="null",
                digest={
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                },
            ).pb,
        ],
        predicate={"Data": "", "Timestamp": "2023-12-07T00:37:58Z"},
        predicate_type="https://cosign.sigstore.dev/attestation/v1",
    )
    res = signer.sign(stmt)
    print(res)
