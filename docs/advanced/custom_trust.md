# Custom Sigstore instances

By default, `sigstore` is configured to work with the public `sigstore.dev`
instance. The trust materials for this instance are bundled with the client,
allowing for a seamless out-of-the-box experience.

In addition to the public instance, `sigstore` also supports using custom
Sigstore instances. When using a custom instance, you are responsible
for providing the trust materials (at least once). This document outlines
the methods for doing so.

### Using a custom instance

Using a custom Sigstore instance is a two-step process:

1.  First, you must establish trust for the new instance. This is done using the
    `sigstore trust-instance` command. This step only needs to be performed once.
2.  Once trust is established, you can use the `--instance` flag with `sigstore`
    commands like `sign` and `verify` to point to your custom instance.

To establish trust for a custom instance, you need its TUF root file. You can then run:

```console
$ sigstore --instance https://my-sigstore.example.com trust-instance my-root.json
```

After successfully adding the new instance, you can use it for signing and verifying
artifacts. For example, to sign a file:

```console
$ sigstore --instance https://my-sigstore.example.com sign foo.txt
```

### Using a custom instance with local configuration

The trust configuration can also be provided as a local file -- but the user is now
responsible for keeping the trust configuration updated.

The `--trust-config` flag, accepts a JSON-formatted file conforming to the `ClientTrustConfig`
message in the [Sigstore protobuf specs](https://github.com/sigstore/protobuf-specs).
This file configures the entire Sigstore instance state, *including* the URIs
used to access the CA and artifact transparency services as well as the
cryptographic root of trust itself.

To use a custom client config, prepend `--trust-config` to any `sigstore`
command:

```console
$ sigstore --trust-config custom.trustconfig.json sign foo.txt
$ sigstore --trust-config custom.trustconfig.json verify identity foo.txt ...
```

### Checkpoint identities in trusted-root v0.2

Trusted roots with media type
`application/vnd.dev.sigstore.trustedroot.v0.2+json` select a Rekor checkpoint
verification key using both the signature's name and its four-byte key ID.
The name must exactly match the log's configured `baseUrl`; URLs are not
normalized, and schemes, paths, ports, and trailing slashes are significant.
Configure the name actually used on the checkpoint signature, rather than
assuming that the log's HTTP endpoint is its signing identity.

The ID comes from `checkpointKeyId.keyId`, or from `logId.keyId` only when
`checkpointKeyId` is absent. The first four decoded bytes are compared with
the signature header, including when a root stores a longer ID. A present
but too-short ID is an error, not a fallback to `logId`. The short ID selects
candidate keys; a valid cryptographic signature is still required. A different
trusted log's key is not tried when the name or ID fails to match.

Unknown checkpoint signatures, such as unconfigured witnesses, are ignored.
A known signature that fails verification rejects the checkpoint, even when
another known signature succeeds. The signed checkpoint origin is not required
to equal its signature name: the checkpoint specification only recommends that
relationship, and legacy Rekor origins include a tree identifier.

Legacy v0.1 roots retain their log-ID-based, name-agnostic lookup. Adding
`checkpointKeyId` to a v0.1 root does not activate the v0.2 behavior. Signed
Entry Timestamps still use their original log-ID-based verification and
canonical payload; checkpoint IDs do not replace log IDs in that payload.
This support does not add witness quorum policy or multi-log thresholds;
bundles must still contain exactly one transparency-log entry.

See the [trusted-root protobuf](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto),
[signed-note identity rules](https://c2sp.org/signed-note@v1.0.0#signatures), and
[checkpoint format](https://c2sp.org/tlog-checkpoint@v1.0.0).
