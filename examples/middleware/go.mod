module github.com/gomaja/go-diameter/examples/middleware

go 1.26

require (
	github.com/gomaja/go-diameter v0.0.0
	github.com/opentracing/opentracing-go v1.2.0
)

require github.com/gomaja/go-sctp v1.1.1-0.20260927070356-42731fdc8a3a // indirect

replace github.com/gomaja/go-diameter => ../..
