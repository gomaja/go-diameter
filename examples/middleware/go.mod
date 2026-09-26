module github.com/gomaja/go-diameter/examples/middleware

go 1.26

require (
	github.com/gomaja/go-diameter v0.0.0
	github.com/opentracing/opentracing-go v1.2.0
)

require github.com/gomaja/go-sctp v1.1.0 // indirect

replace github.com/gomaja/go-diameter => ../..
