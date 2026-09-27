package sm

import (
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestClientWatchdogRoutesAnswersPerConnection(t *testing.T) {
	const peers = 3
	servers := make([]*diamtest.Server, 0, peers)
	connections := make([]diam.Conn, 0, peers)
	requests := make([]chan struct{}, 0, peers)
	defer func() {
		for _, c := range connections {
			c.Close()
		}
		for _, srv := range servers {
			srv.Close()
		}
	}()

	cli := newLivenessClient()
	cli.WatchdogInterval = 30 * time.Millisecond
	for i := 0; i < peers; i++ {
		dwr := make(chan struct{}, 16)
		settings := *serverSettings
		settings.OnDWR = func(diam.Conn, *diam.Message) { dwr <- struct{}{} }
		srv := diamtest.NewServer(New(&settings), dict.Default)
		servers = append(servers, srv)
		requests = append(requests, dwr)
		c, err := cli.Dial(srv.Addr)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, c)
	}

	// Each peer must answer at least twice while all three connections remain
	// live. A shared DWA handler bound to the last Dial starves earlier peers.
	for i, dwr := range requests {
		for n := 0; n < 2; n++ {
			select {
			case <-dwr:
			case <-time.After(time.Second):
				t.Fatalf("peer %d did not receive DWR %d", i, n+1)
			}
		}
	}
	for i, c := range connections {
		select {
		case <-c.(diam.CloseNotifier).CloseNotify():
			t.Fatalf("peer %d closed despite answering its watchdog", i)
		default:
		}
	}
}

func TestClientWatchdogDoesNotCreditAnotherPeersAnswer(t *testing.T) {
	healthy := diamtest.NewServer(New(serverSettings), dict.Default)
	defer healthy.Close()
	silentSM := New(serverSettings)
	silentSM.mux.HandleIdx(baseDWRIdx, handshakeOK(func(diam.Conn, *diam.Message) {}))
	silent := diamtest.NewServer(silentSM, dict.Default)
	defer silent.Close()

	cli := newLivenessClient()
	cli.WatchdogInterval = 30 * time.Millisecond
	healthyConn, err := cli.Dial(healthy.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer healthyConn.Close()
	silentConn, err := cli.Dial(silent.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silentConn.Close()

	select {
	case <-silentConn.(diam.CloseNotifier).CloseNotify():
	case <-time.After(time.Second):
		t.Fatal("unanswered peer remained up")
	}
	select {
	case <-healthyConn.(diam.CloseNotifier).CloseNotify():
		t.Fatal("answering peer closed while another peer was silent")
	default:
	}
}
