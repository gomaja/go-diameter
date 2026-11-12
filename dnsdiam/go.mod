module github.com/gomaja/go-diameter/dnsdiam

go 1.26.0

require (
	codeberg.org/miekg/dns v0.6.97
	github.com/gomaja/go-diameter v0.0.0-20261112070230-cf1e5cc36114
)

require (
	github.com/gomaja/go-ctxsync v0.0.0-20261015170731-23c9cb67b19b // indirect
	github.com/gomaja/go-sctp v0.0.0-20261112061005-2d7d4d9cb936 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/gomaja/go-diameter => ../
