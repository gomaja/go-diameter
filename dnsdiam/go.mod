module github.com/gomaja/go-diameter/dnsdiam

go 1.26.0

require (
	codeberg.org/miekg/dns v0.6.97
	github.com/gomaja/go-diameter v0.0.0-20261014163932-f8bc15879003
)

require (
	github.com/gomaja/go-sctp v0.0.0-20261014114506-6dc7c7827367 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/gomaja/go-diameter => ../
