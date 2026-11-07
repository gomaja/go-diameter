package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestDiscoverySCTPPartialReliabilityRefreshComparison(t *testing.T) {
	for _, network := range []string{"", "tcp", "tcp4", "tcp6", "sctp", "sctp4", "sctp6"} {
		for _, customDial := range []bool{false, true} {
			for _, initial := range []bool{false, true} {
				t.Run(fmt.Sprintf("network=%s/custom-dial=%t/from=%t", network, customDial, initial), func(t *testing.T) {
					manager, actors, sessions := outboundTestManager(t)
					manager.cfg.Clock = &fakeClock{}
					if customDial {
						manager.cfg.Dial = func(context.Context, Endpoint) (net.Conn, error) {
							t.Fatal("refresh must not dial")
							return nil, nil
						}
					}
					a := actors[0]
					spec := discoverySpec()
					spec.Peer = a.cfg
					spec.Peer.Endpoints = []Endpoint{{Network: network, Address: "127.0.0.1:3868", SCTPPartialReliability: initial}}
					first, err := manager.cloneDiscovery(spec)
					if err != nil {
						t.Fatal(err)
					}
					a.discovery.Store(&discoveryState{spec: first, expires: first.ExpiresAt})
					sessions[0].meta = a.meta.Clone()
					if err := a.refreshDiscovery(context.Background(), first); err != nil {
						t.Fatalf("unchanged policy: %v", err)
					}
					spec.Peer.Endpoints[0].SCTPPartialReliability = !initial
					changed, err := manager.cloneDiscovery(spec)
					if err != nil {
						t.Fatal(err)
					}
					err = a.refreshDiscovery(context.Background(), changed)
					if customDial || network == "sctp" || network == "sctp4" || network == "sctp6" {
						if !errors.Is(err, ErrDiscoveryChanged) {
							t.Fatalf("changed transport policy: %v, want ErrDiscoveryChanged", err)
						}
						if a.discovery.Load().spec.Peer.Endpoints[0].SCTPPartialReliability != initial {
							t.Fatal("rejected refresh changed the lease policy")
						}
					} else {
						if err != nil {
							t.Fatalf("ignored TCP policy: %v", err)
						}
						if a.discovery.Load().spec.Peer.Endpoints[0].SCTPPartialReliability != !initial {
							t.Fatal("successful refresh did not publish the new specification")
						}
					}
				})
			}
		}
	}
}
