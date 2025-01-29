module sigstore/sigstore-python

go 1.23.1

toolchain go1.23.5

// We don't have a Go module here but this file is picked up by dependabot
// and this will automatically update the dependency when needed.

require github.com/sigstore/timestamp-authority v1.2.4
