# Offline Verification

!!! danger 
    Because `--offline` disables trust root updates, `sigstore-python` falls back
    to the latest cached trust root or, if none exists, the trust root baked
    into `sigstore-python` itself. Like with any other offline verification,
    this means that users may miss trust root changes (such as new root keys,
    or revocations) unless they separately keep the trust root up-to-date.
    
    Users who need to operationalize offline verification may wish to do this
    by distributing their own trust configuration; see
    [Custom instance with local configuration](./custom_trust.md#using-a-custom-instance-with-local-configuration).

During verification, there are two kinds of network access that `sigstore-python`
*can* perform:

1. When verifying against "detached" materials (e.g. separate `.crt` and `.sig`
   files), `sigstore-python` can perform an online transparency log lookup.
2. By default, during all verifications, `sigstore-python` will attempt to
   refresh the locally cached root of trust via a TUF update.

When performing bundle verification (i.e. `.sigstore` or `.sigstore.json`),
(1) does not apply. However, (2) can still result in online accesses.

To perform **fully** offline verification, pass `--offline` to your
`sigstore verify` subcommand:

```bash
$ sigstore verify identity foo.txt \
    --offline \
    --cert-identity 'hamilcar@example.com' \
    --cert-oidc-issuer 'https://github.com/login/oauth'
```

Alternatively, users may choose to bypass TUF entirely by passing
an entire trust configuration to `sigstore-python` via `--trust-config`:

```bash
$ sigstore --trust-config public.trustconfig.json verify identity ...
```

This will similarly result in fully offline operation, as the trust
configuration contains a full trust root.
