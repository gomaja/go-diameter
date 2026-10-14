package diam

import (
	"context"
	"net"
	"runtime"
	"testing"
)

func testConsecutiveSchedulers(t *testing.T, run func(*testing.T)) {
	t.Helper()
	for _, scheduler := range []struct {
		name  string
		procs int
	}{{"default", 0}, {"one_cpu", 1}} {
		t.Run(scheduler.name, func(t *testing.T) {
			if scheduler.procs > 0 {
				previous := runtime.GOMAXPROCS(scheduler.procs)
				defer runtime.GOMAXPROCS(previous)
			}
			t.Logf("GOMAXPROCS=%d", runtime.GOMAXPROCS(0))
			run(t)
		})
	}
}

func TestAcceptedConsecutiveIdleRestarts(t *testing.T) {
	testConsecutiveSchedulers(t, testAcceptedConsecutiveIdleRestarts)
}

func testAcceptedConsecutiveIdleRestarts(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = local.Close() }()
	defer func() { _ = remote.Close() }()
	transport := &restartTransport{Conn: local, reads: make(chan restartRead, 3), closed: make(chan struct{})}
	transport.reads <- restartRead{err: &TransportRestartError{AssociationID: 7}}
	transport.reads <- restartRead{err: &TransportRestartError{AssociationID: 7}}
	transport.reads <- restartRead{data: cerPayload(t)}
	close(transport.reads)
	var generation uint64
	srv := &Server{Handler: &generationHandler{handle: func(c Conn, _ *Message) {
		generation = c.(ConnLifecycle).Generation()
	}}}
	c := srv.newConn(transport)
	c.accepted = true
	c.serve()
	if generation != 3 {
		t.Fatalf("two restarts with no old callbacks discarded CER: got generation %d, want 3", generation)
	}
}

func TestAcceptedConsecutiveCERRenewals(t *testing.T) {
	testConsecutiveSchedulers(t, testAcceptedConsecutiveCERRenewals)
}

func testAcceptedConsecutiveCERRenewals(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = local.Close() }()
	defer func() { _ = remote.Close() }()
	transport := &restartTransport{Conn: local, reads: make(chan restartRead, 3), closed: make(chan struct{})}
	for range 3 {
		transport.reads <- restartRead{data: cerPayload(t)}
	}
	close(transport.reads)
	type admittedKey struct{}
	var generations []uint64
	srv := &Server{RenewAcceptedCER: true, Handler: &generationHandler{
		eligible: func(c Conn) bool { return c.Context().Value(admittedKey{}) != nil },
		handle: func(c Conn, _ *Message) {
			generations = append(generations, c.(ConnLifecycle).Generation())
			c.SetContext(context.WithValue(c.Context(), admittedKey{}, true))
		},
	}}
	c := srv.newConn(transport)
	c.accepted = true
	c.serve()
	if len(generations) != 3 || generations[2] != 3 {
		t.Fatalf("consecutive CER renewals discarded third CER: got generations %v, want [1 2 3]", generations)
	}
}
