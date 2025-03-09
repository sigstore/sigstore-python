# Signing

!!! warning

    By default signing an artifact creates a public record in `Rekor` which is publicly available.
    The transparency log entry is browsable at `https://search.sigstore.dev/?logIndex=<LOG_INDEX>` 
    and disclose the signing identity.

## Identities

### Signing with ambient credentials

For environments that support OpenID Connect, `sigstore` supports ambient credential
detection. This includes many popular CI platforms and cloud providers. See the full list of
supported environments [here](https://github.com/di/id#supported-environments).

### Signing with an email identity

`sigstore` can use an OAuth2 + OpenID flow to establish an email identity,
allowing you to request signing certificates that attest to control over
that email.

By default, `sigstore` attempts to do [ambient credential detection](#signing-with-ambient-credentials), which may preempt
the OAuth2 flow. To force the OAuth2 flow, you can explicitly disable ambient detection:

```console
$ sigstore sign --oidc-disable-ambient-providers foo.txt
```

### Signing with an explicit identity token

If you can't use an ambient credential or the OAuth2 flow, you can pass a pre-created
identity token directly into `sigstore sign`:

```console
$ sigstore sign --identity-token YOUR-LONG-JWT-HERE foo.txt
```

Note that passing a custom identity token does not circumvent Fulcio's requirements,
namely the Fulcio's supported identity providers and the claims expected within the token.

!!! note

    The examples in the section below are using ambient credential detection.
    When no credentials are detected, it opens a browser to perform an interactive OAuth2 authentication flow.

## Signing an artifact

The easiest option to sign an artifact with `sigstore` is to use the `sign` command.

For example, signing `sigstore-python` [README.md](https://github.com/sigstore/sigstore-python/blob/main/README.md).

```console
$ sigstore sign README.md

Waiting for browser interaction...
Using ephemeral certificate:
-----BEGIN CERTIFICATE-----
MIIC2TCCAl+gAwIBAgIUdqkRnuxTr6bgdKtNiItu3+y8UkIwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjQxMjEyMDk1NTU5WhcNMjQxMjEyMTAwNTU5WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEjb33vsuuNr4phkmpkUvMB19rnXLtS9QqZGT+
kDetyi9+wYv/g2oOFDfEm7UHPLUeZJ6Bad8Zd7H/JqGUhuJ7gaOCAX4wggF6MA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUJpNq
0mPqLw1ypudG98REMY7mjyowHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wLgYDVR0RAQH/BCQwIoEgYWxleGlzLmNoYWxsYW5kZUB0cmFpbG9mYml0cy5j
b20wKQYKKwYBBAGDvzABAQQbaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tMCsG
CisGAQQBg78wAQgEHQwbaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tMIGKBgor
BgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p
7o4AAAGTukvv5QAABAMARzBFAiEA3oqdIinnZ9rGb7CTxQ60G6xi6l3T+z6vkSr2
ERAnIp4CIHbx61camOWU8dClH2WMUfguQ11+D82IQQBnHF968g22MAoGCCqGSM49
BAMDA2gAMGUCMQDdf8S5Y/UhAp2vd2eo+RsjtfsasXSI51kO1ppNz42rSa6b5djW
8+we6/OzVQW+THYCMBaBHPNntloKD040Pce6f8W3HpydbUzshJ24Emt/EaTPqH/g
gYd2xz5hd4vQ7Ysmsg==
-----END CERTIFICATE-----

Transparency log entry created at index: 155016378
MEQCIHVjH0I3iarhB5hD0MEE4AZ7GpCPZhXpdsVsSFlZIynVAiA10qzWt9FBC5pjD6+1kLRS14F+muVD1NJZNw6b+/WADQ==
Sigstore bundle written to README.md.sigstore.json
 
```

The log entry is available at : [https://search.sigstore.dev/?logIndex=155016378](https://search.sigstore.dev/?logIndex=155016378)

## Attest

`sigstore` can be used to generate attestations for software artifacts using [SLSA].

!!! info "What is SLSA?"
    
    Supply-chain Levels for Software Artifacts, or SLSA ("salsa").
    It’s a security framework, a checklist of standards and controls to prevent tampering, improve integrity, and secure packages and infrastructure. It’s how you get from "safe enough" to being as resilient as possible, at any link in the chain.


At the moment, `sigstore` supports the following predicates types:

- [https://slsa.dev/provenance/v1](https://slsa.dev/spec/v1.0/provenance)
- [https://slsa.dev/provenance/v0.2](https://slsa.dev/spec/v0.2/provenance)

Example :

```console
$ sigstore attest \         
    --predicate-type "https://slsa.dev/provenance/v1" \
    --predicate ./test/assets/integration/attest/slsa_predicate_v1_0.json \
    ./README.md
    
Waiting for browser interaction...
Using ephemeral certificate:
-----BEGIN CERTIFICATE-----
MIIC2TCCAmCgAwIBAgIUI1GUnwGV69rXWAixrFmwAcZ7j7IwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjQxMjEyMTAxODUwWhcNMjQxMjEyMTAyODUwWjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEZPieQV37ByUyf+zWMGjXmom+kM4INxPcO1Kf
DhjV3RmhTAlKOYXGU38O/KUNka5BLTb4f5r1bNwGhiEf9qcmNqOCAX8wggF7MA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUUexC
qnLoKejMCAAgNxN77wSlIHkwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wLgYDVR0RAQH/BCQwIoEgYWxleGlzLmNoYWxsYW5kZUB0cmFpbG9mYml0cy5j
b20wKQYKKwYBBAGDvzABAQQbaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tMCsG
CisGAQQBg78wAQgEHQwbaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tMIGLBgor
BgEEAdZ5AgQCBH0EewB5AHcA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p
7o4AAAGTumDcJAAABAMASDBGAiEAprGPiBTcRK8ZFM+x3HLE+2s82xPAecHfJo9F
RXNI+CMCIQCYzRBQtTehd+LLmwkXjPJEsJ5CpI7q1uDhhspyplVSLjAKBggqhkjO
PQQDAwNnADBkAjAjO7BG9Gx6ggm1/IP75l+LzUnAP/DP0BOBeM0/lXZN3BBUvtdq
+oTUzmmY/VpCWggCMEcCMn4UDIF/jBrVhES8ks57T8LjRX6xacpn9ufpkTlnKs6w
S8/kL6jEREOcdnpOSQ==
-----END CERTIFICATE-----

Transparency log entry created at index: 155019253
Sigstore bundle written to README.md.sigstore.json
```

[SLSA]: https://slsa.dev/
