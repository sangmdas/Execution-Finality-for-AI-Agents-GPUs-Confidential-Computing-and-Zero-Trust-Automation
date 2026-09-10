# Go third-party notice

The Go interoperability verifier vendors the following package only to make Unicode NFC normalization reproducible without a network fetch:

- `golang.org/x/text` version `v0.16.0`, specifically `unicode/norm` and its `transform` dependency.

The vendored source was copied from the `vendor/golang.org/x/text` tree shipped with the tested Go 1.23.2 toolchain. Its BSD-3-Clause license is preserved at `vendor/golang.org/x/text/LICENSE`.

The dependency is used to ensure that the Go verifier performs actual NFC normalization rather than merely assuming inputs were already normalized.
