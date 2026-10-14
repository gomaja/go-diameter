module github.com/gomaja/go-diameter

go 1.26.0

require (
	github.com/gomaja/go-sctp v0.0.0-20261014114506-6dc7c7827367
	golang.org/x/sys v0.49.0
)

// Versions the Go module proxy still serves from before this repository
// was maintained here. The module is followed on its main branch.
retract (
	v3.0.2+incompatible // superseded: go get github.com/gomaja/go-diameter@main
	v2.0.3+incompatible // superseded: go get github.com/gomaja/go-diameter@main
	[v1.0.0, v1.1.1] // superseded: go get github.com/gomaja/go-diameter@main
)
