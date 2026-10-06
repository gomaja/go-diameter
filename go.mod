module github.com/gomaja/go-diameter

go 1.26

require (
	github.com/golang/glog v1.2.5
	github.com/golang/protobuf v1.5.4
	github.com/gomaja/go-sctp v1.1.1-0.20260927070356-42731fdc8a3a
	google.golang.org/grpc v1.84.0
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

// Versions the Go module proxy still serves from before this repository
// was maintained here. The module is followed on its main branch.
retract (
	v3.0.2+incompatible // superseded: go get github.com/gomaja/go-diameter@main
	v2.0.3+incompatible // superseded: go get github.com/gomaja/go-diameter@main
	v1.0.0 // superseded: go get github.com/gomaja/go-diameter@main
)
