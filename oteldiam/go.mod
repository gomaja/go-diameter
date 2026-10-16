module github.com/gomaja/go-diameter/oteldiam

go 1.26.0

require (
	github.com/gomaja/go-diameter v0.0.0-20261014213004-95dcab827095
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/log v1.47.0
	go.opentelemetry.io/otel/sdk v1.47.0
	go.opentelemetry.io/otel/sdk/log v1.47.0
	go.opentelemetry.io/otel/trace v1.47.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gomaja/go-ctxsync v0.0.0-20261015170731-23c9cb67b19b // indirect
	github.com/gomaja/go-sctp v0.0.0-20261016073553-b48239f970d4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/gomaja/go-diameter => ../
