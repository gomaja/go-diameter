package peer

import (
	"context"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

func TestReadAnswerPrecedesConnectionGone(t *testing.T) {
	m, err := New(Config{Settings: testSettings("local.example.net")})
	if err != nil {
		t.Fatal(err)
	}
	a := &actor{m: m, cfg: PeerConfig{Host: "a.example.net"}, events: make(chan event, 8), done: make(chan struct{}), state: IOpen, watchdog: WatchdogOkay, meta: &smpeer.Metadata{OriginHost: "a.example.net", OriginRealm: "example.net", Applications: []uint32{4}}}
	c := newFakeConn()
	s := &session{m: m, c: c, actor: a, gen: 1, writes: make(chan writeRequest, 8), ingress: make(chan incoming, 8), closed: make(chan struct{})}
	a.active, a.i = s, s
	a.publish(nil)
	m.peers[identity(a.cfg.Host)] = a
	m.sessions[c] = s
	startedActor := false
	startActor := func() {
		if !startedActor {
			startedActor = true
			m.wg.Add(1)
			go a.run()
		}
	}
	t.Cleanup(func() { startActor(); closeManager(t, m, nil) })
	if err := m.SetRoutes([]Route{{Realm: "example.net", ApplicationID: 4, PeerHosts: []datatype.DiameterIdentity{"a.example.net"}}}); err != nil {
		t.Fatal(err)
	}
	watchDone := make(chan struct{})
	m.wg.Add(1)
	go func() { s.watch(); close(watchDone) }()
	result := sendAsync(m, context.Background(), outboundRequest("", "example.net"))
	request := nextWrite(t, s)
	answer := request.Answer(diam.Success)
	m.ServeDIAM(c, answer)
	if len(s.ingress) != 1 {
		t.Fatal("answer was not queued before close")
	}
	c.Close()
	select {
	case <-watchDone:
	case <-time.After(time.Second):
		t.Fatal("close watcher stalled")
	}
	if s.enqueue(answer) {
		t.Fatal("message admitted after close sealed ordered ingress")
	}
	dispatchDone := make(chan struct{})
	m.wg.Add(1)
	go func() { s.dispatch(); close(dispatchDone) }()
	select {
	case <-dispatchDone:
	case <-time.After(time.Second):
		t.Fatal("ordered ingress did not drain")
	}
	startActor()
	select {
	case got := <-result:
		if got.err != nil || got.answer != answer {
			t.Fatalf("read answer lost to connection close: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("request did not complete")
	}
}
