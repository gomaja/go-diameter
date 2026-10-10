//go:build linux && !386

package sm

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-sctp"
)

func TestPreHookCloseSCTPInEveryWiring(t *testing.T) {
	requireSCTP(t)
	testPreHookCloseInEveryWiring(t, "sctp", func(addr string) (net.Conn, error) {
		remote, err := sctp.ResolveAddr("sctp", addr)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return sctp.Dial(ctx, "sctp", nil, remote)
	})
}
