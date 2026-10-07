package sm

import (
	"errors"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

func TestConcurrentClientDialsRouteCEAToTheirOwnHandshake(t *testing.T) {
	const peers = 3
	type result struct {
		peer int
		conn diam.Conn
		err  error
	}
	cancel := make(chan struct{})
	results := make(chan result, peers)
	servers := make([]*diamtest.Server, 0, peers)
	gates := make([]chan struct{}, 0, peers)
	seen := make([]chan struct{}, 0, peers)
	t.Cleanup(func() {
		close(cancel)
		for _, srv := range servers {
			srv.Close()
		}
	})

	for i := 0; i < peers; i++ {
		gate := make(chan struct{})
		entered := make(chan struct{}, 1)
		serverSM := mustNewStateMachine(t, serverSettings)
		mux := diam.NewServeMux()
		peer := i
		mux.HandleFunc("CER", func(c diam.Conn, m *diam.Message) {
			entered <- struct{}{}
			select {
			case <-gate:
			case <-cancel:
				return
			}
			var err error
			if peer == 1 {
				err = errorCEA(serverSM, c, m, smparser.ErrNoCommonApplication)
			} else {
				handleCER(serverSM)(c, m)
			}
			if err != nil {
				t.Errorf("peer %d CEA: %v", peer, err)
			}
		})
		servers = append(servers, diamtest.NewServer(mux, dict.Default))
		gates = append(gates, gate)
		seen = append(seen, entered)
	}

	cli := newLivenessClient(t)
	cli.EnableWatchdog = false
	cli.RetransmitInterval = 2 * time.Second
	for i, srv := range servers {
		peer := i
		go func() {
			c, err := cli.Dial(srv.Addr)
			results <- result{peer: peer, conn: c, err: err}
		}()
		select {
		case <-seen[i]:
		case <-time.After(time.Second):
			t.Fatalf("peer %d did not receive CER", i)
		}
	}

	// The final dial installed the last shared handler in the broken code.
	// Release the middle peer's error CEA first; it must reach that dial.
	close(gates[1])
	for _, want := range []int{1, 0, 2} {
		if want != 1 {
			close(gates[want])
		}
		select {
		case got := <-results:
			if got.conn != nil {
				defer got.conn.Close()
			}
			if got.peer != want {
				t.Fatalf("CEA from peer %d completed dial to peer %d", want, got.peer)
			}
			if want == 1 {
				var failed *smparser.ErrFailedResultCode
				if !errors.As(got.err, &failed) || failed.ResultCode != diam.NoCommonApplication {
					t.Fatalf("peer %d result = %v, want no common application", want, got.err)
				}
			} else if got.err != nil {
				t.Fatalf("peer %d handshake failed: %v", want, got.err)
			}
		case <-time.After(time.Second):
			t.Fatalf("peer %d did not receive its CEA", want)
		}
	}
}

func TestConcurrentClientDialsWithDefaultSettings(t *testing.T) {
	srv := diamtest.NewServer(mustNewStateMachine(t, serverSettings), dict.Default)
	defer srv.Close()
	cli := newLivenessClient(t)
	cli.EnableWatchdog = false
	cli.Dict = nil
	cli.RetransmitInterval = 0
	cli.WatchdogInterval = 0
	const peers = 8
	type result struct {
		conn diam.Conn
		err  error
	}
	results := make(chan result, peers)
	for i := 0; i < peers; i++ {
		go func() {
			c, err := cli.Dial(srv.Addr)
			results <- result{c, err}
		}()
	}
	for i := 0; i < peers; i++ {
		select {
		case got := <-results:
			if got.err != nil {
				t.Fatal(got.err)
			}
			got.conn.Close()
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent Dial did not finish")
		}
	}
}
