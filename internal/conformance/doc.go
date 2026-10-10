// Package conformance reads what fsagen writes with parsers fsagen did not
// write: third-party Go libraries for each binary format, so a file is
// checked by someone else's reading of the specification as well as by the
// reader in fsagen's own tests.
//
// It is a module of its own, so those libraries are dependencies of this
// test suite and never of fsagen: the root go.mod lists only what the product
// needs. The gate runs it with
//
//	go -C internal/conformance test ./...
package conformance
