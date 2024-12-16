# Custom Root of Trust

### Configuring a custom root of trust ("BYO PKI")

Apart from the default and "staging" Sigstore instances, `sigstore` also
supports "BYO PKI" setups, where a user maintains their own Sigstore
instance services.

These are supported via the `--trust-config` flag, which accepts a
JSON-formatted file conforming to the `ClientTrustConfig` message
in the [Sigstore protobuf specs](https://github.com/sigstore/protobuf-specs).
This file configures the entire Sigstore instance state, *including* the URIs
used to access the CA and artifact transparency services as well as the
cryptographic root of trust itself.

To use a custom client config, prepend `--trust-config` to any `sigstore`
command:

```console
$ sigstore --trust-config custom.trustconfig.json sign foo.txt
$ sigstore --trust-config custom.trustconfig.json verify identity foo.txt ...
```