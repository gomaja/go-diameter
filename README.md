# go-diameter

[![CI Status](https://github.com/gomaja/go-diameter/actions/workflows/ci.yml/badge.svg)](https://github.com/gomaja/go-diameter/actions/workflows/ci.yml)
[![Security](https://github.com/gomaja/go-diameter/actions/workflows/security.yml/badge.svg)](https://github.com/gomaja/go-diameter/actions/workflows/security.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/gomaja/go-diameter.svg)](https://pkg.go.dev/github.com/gomaja/go-diameter)

`go-diameter` is a standards-first Diameter stack for Go. It provides message
encoding and decoding, AVP data types, XML dictionaries, client and server APIs,
peer state machines, test helpers, and examples for building Diameter clients,
servers, and agents.

The module path is:

```sh
go get github.com/gomaja/go-diameter
```

## Why This Library

- Implements the Diameter base protocol model with Go-native APIs for messages,
  AVPs, dictionaries, handlers, clients, and servers.
- Tracks the current Diameter RFC set and verified errata instead of relying on
  obsolete RFC references.
- Uses `github.com/gomaja/go-sctp` for Linux SCTP support, with TCP and TLS
  support available through the standard Go networking stack.
- Ships with practical examples for clients, servers, SCTP, snooping, grouped
  AVPs, S6a, middleware, Wireshark dictionary conversion, and benchmarking.
- Maintains public CI and security gates covering formatting, Linux tests,
  race tests, vet, cross-architecture vet, static analysis, vulnerability
  scanning, CodeQL, and secret detection.

## Quick Start

Run the sample server:

```sh
go run github.com/gomaja/go-diameter/examples/server@latest
```

In another terminal, run the sample client and send a request:

```sh
go run github.com/gomaja/go-diameter/examples/client@latest -hello
```

The examples load a small custom dictionary on top of the default Diameter
dictionaries, perform CER/CEA capability exchange, send a request, and handle
the answer.

## Package Map

- `diam`: core message, AVP, client, server, transport, and handler APIs.
- `diam/avp`: Diameter AVP codes and flags.
- `diam/datatype`: Diameter AVP data types such as `UTF8String`,
  `Unsigned32`, `DiameterIdentity`, `Address`, and grouped values.
- `diam/dict`: XML dictionary parser and embedded default dictionaries.
- `diam/sm`: peer state machines for CER/CEA and DWR/DWA handling.
- `diam/sm/smparser`: helpers for parsing state-machine messages.
- `diam/sm/smpeer`: peer metadata attached to accepted connections.
- `diam/diamtest`: server test helpers analogous to `net/http/httptest`.

See the full API documentation at
[pkg.go.dev/github.com/gomaja/go-diameter](https://pkg.go.dev/github.com/gomaja/go-diameter).

## Standards Posture

The library is maintained against the current published Diameter specifications,
their updates, and verified errata. Standards-sensitive changes should be tied
to exact document sections and, where relevant, errata IDs.

Core IETF references:

- [RFC 6733](https://www.rfc-editor.org/rfc/rfc6733): Diameter Base Protocol.
- [RFC 7075](https://www.rfc-editor.org/rfc/rfc7075): update to RFC 6733.
- [RFC 8553](https://www.rfc-editor.org/rfc/rfc8553): update to RFC 6733.
- [RFC 8506](https://www.rfc-editor.org/rfc/rfc8506): Diameter
  Credit-Control Application.
- [RFC 7155](https://www.rfc-editor.org/rfc/rfc7155): Diameter Network Access
  Server Application.
- [RFC 5516](https://www.rfc-editor.org/rfc/rfc5516): 3GPP EPS Diameter
  command-code registration.

The embedded dictionary set also includes application dictionaries for:

- Base protocol.
- Credit-Control.
- Gx.
- Network Access Server.
- 3GPP Ro/Rf.
- 3GPP Rx.
- 3GPP S6a.
- 3GPP S13.
- 3GPP SWx.
- Diameter Sy.

Dictionaries make application AVPs and commands available to the stack. They do
not replace the application-specific business logic, session policy, charging
logic, or deployment rules required by an operator system.

3GPP dictionary coverage is release-sensitive. Validate the dictionary and any
application behavior against the exact 3GPP or ETSI release used by the target
network before claiming interface compliance for a deployment.

## Transport Support

`go-diameter` supports Diameter over:

- TCP.
- TCP with TLS.
- SCTP on Linux, through `github.com/gomaja/go-sctp` and the host kernel SCTP
  implementation.

SCTP is a Linux runtime feature. Non-Linux builds are kept portable, but
socket-backed SCTP behavior must be validated on Linux with SCTP enabled.

## Validation

The public CI pipeline validates the repository with:

- `gofmt` and whitespace checks.
- Linux tests on Go 1.25.x and stable Go.
- Linux race tests.
- `go vet`.
- Cross-architecture vet for selected Linux targets.
- `staticcheck`.
- `golangci-lint`.
- `govulncheck`.
- macOS and Windows portability tests for unsupported SCTP platforms.

The security pipeline adds:

- Dependency review for pull requests.
- Scheduled dependency scanning.
- CodeQL SAST with extended Go queries.
- Secret detection with gitleaks.

## Performance

Throughput depends heavily on application structure, logging, dictionary lookup
patterns, reflection use, TLS, and transport choice. The repository includes Go
benchmarks and a benchmark-capable client example:

```sh
go run github.com/gomaja/go-diameter/examples/client@latest -bench
```

For realistic performance tests, avoid logging full Diameter messages in hot
paths. Pretty-printing messages is useful for debugging, but it performs
additional conversions that distort throughput measurements.

## Contributing

Keep changes small, standards-linked, and testable.

When adding or changing AVPs:

1. Update the XML dictionaries under `diam/dict/testdata`.
2. Regenerate dictionary code:

   ```sh
   make gen_diam
   ```

3. Review the generated changes under `diam/dict`.

For Go code changes, run the full local validation set before opening a pull
request:

```sh
go build ./...
go test ./... -count=1
go vet ./...
staticcheck ./...
golangci-lint run ./...
```

SCTP changes must also be validated on Linux with SCTP enabled. A passing macOS
or Windows run only proves unsupported-platform portability, not SCTP runtime
behavior.

## License

`go-diameter` is distributed under the BSD-style license in [LICENSE](LICENSE).
