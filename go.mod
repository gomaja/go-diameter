module github.com/gomaja/go-diameter

go 1.26.0

require (
	github.com/gomaja/go-sctp v1.1.1-0.20260927070356-42731fdc8a3a
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261005182115-fad411399dd8 // indirect
)

// Versions the Go module proxy still serves from before this repository
// was maintained here. The module is followed on its main branch.
retract (
	v3.0.2+incompatible // superseded: go get github.com/gomaja/go-diameter@main
	v2.0.3+incompatible // superseded: go get github.com/gomaja/go-diameter@main
	v1.0.0 // superseded: go get github.com/gomaja/go-diameter@main
)
