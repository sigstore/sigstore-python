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