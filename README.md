# go-diameter

[![CI Status](https://github.com/gomaja/go-diameter/actions/workflows/ci.yml/badge.svg)](https://github.com/gomaja/go-diameter/actions/workflows/ci.yml)
[![Security](https://github.com/gomaja/go-diameter/actions/workflows/security.yml/badge.svg)](https://github.com/gomaja/go-diameter/actions/workflows/security.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/gomaja/go-diameter.svg)](https://pkg.go.dev/github.com/gomaja/go-diameter)

`go-diameter` is a standards-first Diameter stack for Go. It provides message
encoding and decoding, AVP data types, XML dictionaries, client and server APIs,
peer state machines, test helpers, and examples for building Diameter clients,
servers, and agents.

## Installing

This module is followed on its `main` branch. It has no releases. Go 1.26 or
later is required, and its go-sctp dependency is followed on `main` too.

```sh
go get github.com/gomaja/go-diameter@main
```

Use `@main`, not `@latest`, to get the module and to update it. The Go
module proxy still serves versions published before this repository was
maintained here (`v1.0.0`, `v2.0.3+incompatible` and `v3.0.2+incompatible`).
One tag, `v1.1.0`, placed on `main` when go-diameter moved to go-sctp's
current API, holds their retraction in its `go.mod` (Go reads retractions
only from the newest version) and keeps `main`'s pseudo-versions sorting
above them; no other tag follows it. `@latest`, and any tool that follows
releases, resolves to that tag. Later commits are reached only with `@main`
or a commit hash, and `go get -u` does not move a module from one `main`
commit to a newer one.

## Why This Library

- Implements the Diameter base protocol model with Go-native APIs for messages,
  AVPs, dictionaries, handlers, clients, and servers.
- Tracks the current Diameter RFC set and verified errata instead of relying on
  obsolete RFC references.
- Uses `github.com/gomaja/go-sctp` for Linux SCTP support, with TCP and TLS
  support available through the standard Go networking stack.
- Writes structured `log/slog` records to a logger you inject.
- Ships with practical examples for clients, servers, SCTP, snooping, grouped
  AVPs, S6a, OpenTelemetry tracing middleware, Wireshark dictionary
  conversion, and benchmarking.
- Maintains public CI and security gates covering formatting, Linux tests,
  race tests, vet, cross-architecture vet, static analysis, vulnerability
  scanning, CodeQL, and secret detection.

## Quick Start

Run the sample server:

```sh
go run github.com/gomaja/go-diameter/examples/server@main
```

In another terminal, run the sample client and send a request:

```sh
go run github.com/gomaja/go-diameter/examples/client@main -hello
```

The examples load a small custom dictionary on top of the default Diameter
dictionaries, perform CER/CEA capability exchange, send a request, and handle
the answer.

## Package Map

- `diam`: core message, AVP, client, server, transport, and handler APIs.
- `diam/avp`: Diameter AVP codes and flags.
- `diam/datatype`: Diameter AVP data types such as `UTF8String`,
  `Unsigned32`, `DiameterIdentity`, `Address`, and grouped values.
- `diam/dict`: XML dictionary parser, embedded dictionaries that can be
  selected with automatic dependency inclusion (for Gx, `dict.New(dict.Gx)`),
  and AVP registration at runtime. Dictionaries can change while messages
  are decoded.
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
- 3GPP Cx/Dx (TS 29.229 V19.1.0).
- 3GPP Sh (TS 29.329 V19.1.0).
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

### Dictionary Inheritance

An application declares the applications whose AVPs it reuses in XML, for
example `<application id="3" name="Base Accounting" inherits="4">`. The
`inherits` attribute holds one or more whitespace-separated decimal
application IDs from 0 through 4294967294; omit it for none. An empty
attribute, signs, commas and hexadecimal notation are rejected. Repeated
declarations of one application contribute an ordered union of parents, and
duplicates are ignored.

An application's own AVPs take precedence, then its ancestors in breadth-first
parent order, with base application 0 always last. Commands and vendor
declarations are not inherited; command lookup keeps its separate base
fallback. An application no dictionary declares falls back only to base, even
when it uses a familiar bundled ID. A custom dictionary that uses another
application's AVPs in its rules names that application in `inherits`.

Inheritance is resolved when a dictionary snapshot is built, and any of these
rejects the whole load or registration, leaving the current snapshot in place:

- a non-base parent no dictionary declares in this load or an earlier one
  (`dict.ErrNotFound`, naming the child and the parent); registration alone
  does not declare an application;
- the Relay identifier 4294967295 (RFC 6733 §2.4) as a parent, even if
  declared;
- a cycle, including base inheriting another application
  (`dict.ErrParentCycle`);
- two non-base direct parents resolving a name to different code/vendor
  identities in their final views, unless the child defines that name itself
  in loaded or registered AVPs (`dict.ErrAVPConflict`, naming the child, the
  name, both parents and both identities).

Each parent's final view includes its own ancestors and the base fallback, so
base 0 is never compared as a parent of its own, whether listed or implicit;
`inherits="0"` is valid without base.xml and does not change the order. A
single parent may shadow a base name, but that conflicts with a second parent
that still resolves the name to base, unless the child defines it itself.

The check covers names, which rules use. A code/vendor that several ancestors
define differently, for example with other flags or another type, takes the
definition of the first ancestor in breadth-first order that defines it
itself, so the order of `inherits` matters. With `inherits="16777238
16777236"` (Gx, then Rx) 3GPP-SGSN-MCC-MNC requires M and V as in Gx; with
Rx listed first it requires V and forbids M as in Rx.

Own AVP names are unique. Along one inheritance chain a nearer application may
give its own AVP an ancestor's name: Sh's User-Data 702/10415 (TS 29.329
V19.1.0 §6.3.3) shadows Cx's User-Data 606/10415 (TS 29.229 V19.1.0 §6.3.7),
and 606 still decodes in Sh by its code. A nearer definition may also rename
an inherited code/vendor, after which the old name no longer resolves.

Ro/Rf's contribution to application 3 gives Rf accounting its charging
definitions. Selections without Ro/Rf, such as Base, NASREQ, Cx and Sh, keep
the 63 base accounting AVPs.

## Transport Support

`go-diameter` supports Diameter over:

- TCP.
- TCP with TLS.
- SCTP on Linux, through `github.com/gomaja/go-sctp` and the host kernel SCTP
  implementation.

SCTP is a Linux runtime feature. Non-Linux builds are kept portable, but
socket-backed SCTP behavior must be validated on Linux with SCTP enabled.

SCTP needs Linux 5.0 or later, the same floor as go-sctp. The main deployment
target is Rocky Linux 9, which runs a 5.14 kernel.

On Rocky Linux 9, and on other RHEL 9 derivatives, SCTP is not available out
of the box. The `sctp` module ships in the `kernel-modules-extra` package,
and that package also blacklists it, because unprivileged users could
otherwise load it (see Red Hat's article 3760101). Until an administrator
enables it, SCTP sockets fail with "protocol not supported"
(`EPROTONOSUPPORT`). To enable it, install the package for the running
kernel and comment out the blacklist line:

```sh
sudo dnf install "kernel-modules-extra-$(uname -r)"
sudo sed -i 's/^blacklist sctp$/#blacklist sctp/' /etc/modprobe.d/sctp-blacklist.conf
```

No reboot is needed: the module loads the first time an SCTP socket is
opened. `/proc/net/sctp/snmp` exists once it is loaded.

## Validation

The public CI pipeline validates the repository with:

- `gofmt` and whitespace checks.
- Linux tests on Go 1.26.x and stable Go.
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

## Logging and Tracing

`diam.Server`, `sm.Client` and `peer.Config` each expose a `Logger *slog.Logger`.
Connection handlers use `Conn.Logger()`, which adds network and address attributes.
A nil logger resolves `slog.Default()` for each call; use
`slog.New(slog.DiscardHandler)` to discard records.

Records are synchronous: a slow `slog.Handler` slows the detecting goroutine.
Diagnostic records are emitted directly without a library report queue or sampling.
During server shutdown, new messages other than DPA are discarded without a
per-message record. A custom logging handler can inspect the retained `error`
value with `errors.As`. The `message` group contains header metadata only, never
AVPs.

Malformed messages produce Warn records before optional error handling. Each
component records its own close decision before closing; asynchronous peer
answer failures are reported by the peer manager. State-machine unsupported
requests answered with 3001/3007 are Info, unmatched answers and protocol faults
are Warn, and local failures or recovered panics are Error. Transport read
failures and close failures are Debug; bare EOF and errors wrapping
`net.ErrClosed` are quiet. A wrapped EOF still records a truncated read at Debug.
Peer event-queue overflow produces a Warn record.

Use `CloseNotify` for disconnects, watchdog hooks for liveness, `OnPeerEvent` for
managed peers, and an `ALL` handler for unmatched messages. `Settings.OnHandshake`
runs once after successful CER/CEA exchange while admission is held. It must not
wait for later messages on that connection or call `Disconnect` for it.

Middleware should expose `Unwrap() diam.Handler`. `diam.HandlerAs` then discovers
optional accept and malformed-message handlers through the wrapper. Those calls
bypass an Unwrap-only wrapper. A wrapper that intercepts an optional method must
delegate it synchronously or take responsibility itself. `ServeDIAM` forwarding
must remain synchronous to retain message admission order. An `sm.StateMachine`
must be the server handler or beneath Unwrap wrappers to start the handshake
timeout. Opaque wrappers and mux routes still reject pre-CER traffic, but cannot
start that timeout and remain unsupported wiring.

Registrations panic for empty names, nil handlers, duplicates, and reserved
state-machine commands. Short names span applications (for example, S6a and Sh
`PUR`); use `HandleIdx` with an application ID for a specific application.

```go
srv := &diam.Server{
	Handler: mux,
	Logger:  slog.New(slog.NewJSONHandler(os.Stderr, nil)),
}
```

The `examples/middleware` module wraps a handler with OpenTelemetry tracing:
one span per message, with the Diameter application, command and result as
attributes. When the handler panics, the span ends with status Error and an
`error.type`. The panic is recorded as one `exception` log record, at
severity ERROR, carrying the span's context, through the OpenTelemetry Logs
API. It is not recorded as a span event, which the semantic conventions
deprecate ([exceptions in logs](https://opentelemetry.io/docs/specs/semconv/exceptions/exceptions-logs/),
[recording errors](https://opentelemetry.io/docs/specs/semconv/general/recording-errors/)).
The panic then continues to `diam.Server`. `WithTracerProvider` and
`WithLoggerProvider` choose the providers; the defaults are the global ones.

## Performance

Throughput depends heavily on application structure, logging, dictionary lookup
patterns, reflection use, TLS, and transport choice. The repository includes Go
benchmarks and a benchmark-capable client example:

```sh
go run github.com/gomaja/go-diameter/examples/client@main -bench
```

For realistic performance tests, avoid logging full Diameter messages in hot
paths. Pretty-printing messages is useful for debugging, but it performs
additional conversions that distort throughput measurements.

## Contributing

Keep changes small, standards-linked, and testable.

When adding or changing AVPs:

1. Update the XML dictionaries under `diam/dict/bundled`. Package `dict`
   embeds them as they are. A new dictionary file also needs its named
   `dict.Bundled` constant and dependency entry in `diam/dict/bundled.go`.
2. Regenerate the command, application and AVP code constants:

   ```sh
   make gen_diam
   ```

3. Review the generated changes under `diam`.

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
