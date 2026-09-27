package peer

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm"
)

func TestRFC6733StateTable(t *testing.T) {
	cases := []struct {
		state  PeerState
		events string
		next   string
	}{
		{Closed, "Start,R-Conn-CER", "Wait-Conn-Ack,R-Open"},
		{WaitConnAck, "I-Rcv-Conn-Ack,I-Rcv-Conn-Nack,R-Conn-CER,Timeout", "Wait-I-CEA,Closed,Wait-Conn-Ack/Elect,Closed"},
		{WaitICEA, "I-Rcv-CEA,R-Conn-CER,I-Peer-Disc,I-Rcv-Non-CEA,Timeout", "I-Open,Wait-Returns,Closed,Closed,Closed"},
		{WaitConnAckElect, "I-Rcv-Conn-Ack,I-Rcv-Conn-Nack,R-Peer-Disc,R-Conn-CER,Timeout", "Wait-Returns,R-Open,Wait-Conn-Ack,Wait-Conn-Ack/Elect,Closed"},
		{WaitReturns, "Win-Election,I-Peer-Disc,I-Rcv-CEA,R-Peer-Disc,R-Conn-CER,Timeout", "R-Open,R-Open,I-Open,Wait-I-CEA,Wait-Returns,Closed"},
		{ROpen, "Send-Message,R-Rcv-Message,R-Rcv-DWR,R-Rcv-DWA,R-Conn-CER,Stop,R-Rcv-DPR,R-Peer-Disc", "R-Open,R-Open,R-Open,R-Open,R-Open,Closing,Closing,Closed"},
		{IOpen, "Send-Message,I-Rcv-Message,I-Rcv-DWR,I-Rcv-DWA,R-Conn-CER,Stop,I-Rcv-DPR,I-Peer-Disc", "I-Open,I-Open,I-Open,I-Open,I-Open,Closing,Closing,Closed"},
		{Closing, "I-Rcv-DPA,R-Rcv-DPA,Timeout,I-Peer-Disc,R-Peer-Disc", "Closed,Closed,Closed,Closed,Closed"},
	}
	count := 0
	for _, tc := range cases {
		events := split(tc.events)
		next := split(tc.next)
		if len(events) != len(next) {
			t.Fatal(tc.state)
		}
		for i, e := range events {
			t.Run(string(tc.state)+"/"+e, func(t *testing.T) {
				row, ok := transition(tc.state, psmEvent(e))
				if !ok || row.next != PeerState(next[i]) || row.actions == "" {
					t.Fatalf("row=%+v ok=%v", row, ok)
				}
			})
			count++
		}
	}
	if count != 43 {
		t.Fatalf("tested %d rows, want 43", count)
	}
}
func split(s string) []string {
	var out []string
	start := 0
	for i, c := range s {
		if c == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
func TestElectionASCIIOctets(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{{"z.EXAMPLE", "A.example", 1}, {"A.example", "z.EXAMPLE", -1}, {"a.Example", "A.eXAMPLE", 0}, {"a.example", "a.example2", -1}} {
		got := compareIdentity(datatype.DiameterIdentity(tc.a), datatype.DiameterIdentity(tc.b))
		if got != tc.want {
			t.Fatalf("%q/%q=%d", tc.a, tc.b, got)
		}
	}
}

func TestManagersSimultaneousTCP(t *testing.T) {
	t.Run("local-loses", func(t *testing.T) { testManagersSimultaneous(t, "tcp", "a.example.net", "b.example.net", false) })
	t.Run("local-wins", func(t *testing.T) { testManagersSimultaneous(t, "tcp", "z.example.net", "a.example.net", false) })
	t.Run("endpoint-fallback", func(t *testing.T) { testManagersSimultaneous(t, "tcp", "a.example.net", "b.example.net", true) })
}
func TestManagersSimultaneousSCTP(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("SCTP sockets require Linux")
	}
	testManagersSimultaneous(t, "sctp", "a.example.net", "b.example.net", false)
}
func testManagersSimultaneous(t *testing.T, network, hostA, hostB string, fallback bool) {
	t.Helper()
	before := runtime.NumGoroutine()
	listen := func() (net.Listener, error) {
		if network == "sctp" {
			return diam.MultistreamListen("sctp", "127.0.0.1:0")
		}
		return net.Listen("tcp", "127.0.0.1:0")
	}
	la, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	lb, err := listen()
	if err != nil {
		t.Fatal(err)
	}
	settings := func(host string) sm.Settings {
		return sm.Settings{OriginHost: datatype.DiameterIdentity(host), OriginRealm: "example.net", VendorID: 1, ProductName: "peer-test"}
	}
	ma, err := New(Config{Settings: settings(hostA)})
	if err != nil {
		t.Fatal(err)
	}
	mb, err := New(Config{Settings: settings(hostB)})
	if err != nil {
		t.Fatal(err)
	}
	endpoints := []Endpoint{{Network: network, Address: lb.Addr().String()}}
	if fallback {
		endpoints = append([]Endpoint{{Network: network, Address: "127.0.0.1:1"}}, endpoints...)
	}
	if err := ma.AddPeer(PeerConfig{Host: datatype.DiameterIdentity(hostB), Endpoints: endpoints}); err != nil {
		t.Fatal(err)
	}
	if err := mb.AddPeer(PeerConfig{Host: datatype.DiameterIdentity(hostA), Endpoints: []Endpoint{{Network: network, Address: la.Addr().String()}}}); err != nil {
		t.Fatal(err)
	}
	sa, sb := &diam.Server{}, &diam.Server{}
	if err := ma.BindServer(sa); err != nil {
		t.Fatal(err)
	}
	if err := mb.BindServer(sb); err != nil {
		t.Fatal(err)
	}
	go func() { _ = sa.Serve(la) }()
	go func() { _ = sb.Serve(lb) }()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := ma.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := mb.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	wantA, wantB := IOpen, ROpen
	if compareIdentity(datatype.DiameterIdentity(hostA), datatype.DiameterIdentity(hostB)) > 0 {
		wantA, wantB = ROpen, IOpen
	}
	for {
		pa, pb := ma.Peers()[0], mb.Peers()[0]
		if pa.State == wantA && pb.State == wantB {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not open: %+v %+v; want %s/%s", pa, pb, wantA, wantB)
		}
		time.Sleep(10 * time.Millisecond)
	}
	started := time.Now()
	if err := ma.Close(ctx, sm.DisconnectRebooting); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("DPR/DPA did not close promptly")
	}
	if err := mb.Close(ctx, sm.DisconnectRebooting); err != nil {
		t.Fatal(err)
	}
	_ = sa.Close()
	_ = sb.Close()
	time.Sleep(100 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+5 {
		t.Fatalf("goroutines before=%d after=%d", before, after)
	}
}
func TestStaleCandidateEventsIgnored(t *testing.T) {
	m, err := New(Config{Settings: sm.Settings{OriginHost: "local.example.net", OriginRealm: "example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	a := &actor{m: m, cfg: PeerConfig{Host: "peer.example.net"}, state: ROpen, done: make(chan struct{}), token: 7}
	winner := &session{gen: 3}
	loser := &session{gen: 2}
	a.r = winner
	a.active = winner
	a.publish(nil)
	a.onGone(loser)
	a.onWire(event{kind: wireEvent, s: loser, msg: diam.NewRequest(diam.CapabilitiesExchange, 0, nil)})
	a.handle(event{kind: timeout, token: 6})
	if a.state != ROpen || a.active != winner {
		t.Fatalf("stale candidate changed winner: %+v", a.snapshot())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Close(ctx, sm.DisconnectRebooting); err != nil {
		t.Fatal(err)
	}
}
func TestEqualIdentityRejected(t *testing.T) {
	m, err := New(Config{Settings: sm.Settings{OriginHost: "LOCAL.example.net", OriginRealm: "example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddPeer(PeerConfig{Host: "local.EXAMPLE.net"}); err == nil {
		t.Fatal("accepted identity collision")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Close(ctx, sm.DisconnectRebooting); err != nil {
		t.Fatal(err)
	}
}

func TestCloseRespectsContextWithBlockedObserver(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	m, err := New(Config{Settings: sm.Settings{OriginHost: "local.example.net", OriginRealm: "example.net"}, OnPeerEvent: func(PeerEvent) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddPeer(PeerConfig{Host: "peer.example.net"}); err != nil {
		t.Fatal(err)
	}
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.Close(ctx, sm.DisconnectRebooting); err != context.DeadlineExceeded {
		t.Fatalf("Close error=%v", err)
	}
	close(release)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := m.Close(ctx2, sm.DisconnectRebooting); err != nil {
		t.Fatal(err)
	}
}
