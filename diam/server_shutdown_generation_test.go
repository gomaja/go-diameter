package diam

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

type shutdownRetirementTransport struct {
	*fencedMultistream
	reset      func()
	closeCalls atomic.Int32
}

func (c *shutdownRetirementTransport) ResetForRestart() {
	if c.reset != nil {
		c.reset()
	}
}

func (c *shutdownRetirementTransport) Close() error {
	c.closeCalls.Add(1)
	return c.fencedMultistream.Close()
}

// Holding Done until serve exits forces Shutdown's worker to observe the
// completed old generation before it can choose its next action.
type retirementShutdownContext struct {
	context.Context
	entered chan struct{}
	served  <-chan struct{}
	once    sync.Once
}

func (c *retirementShutdownContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	<-c.served
	return c.Context.Done()
}

func TestShutdownRetirementClosesPhysical(t *testing.T) {
	for _, stage := range []string{"retire", "reset"} {
		for _, mode := range []int{0, -1} {
			t.Run(fmt.Sprintf("%s/%d", stage, mode), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					local, remote := net.Pipe()
					raw := &restartTransport{Conn: local, reads: make(chan restartRead, 3), closed: make(chan struct{})}
					transport := &shutdownRetirementTransport{fencedMultistream: &fencedMultistream{Conn: raw}}
					entered, release := make(chan struct{}), make(chan struct{})
					callbackEntered, callbackRelease := make(chan struct{}), make(chan struct{})
					var releaseOnce, callbackOnce sync.Once
					unblock := func() { releaseOnce.Do(func() { close(release) }) }
					unblockCallback := func() { callbackOnce.Do(func() { close(callbackRelease) }) }
					pause := func() { close(entered); <-release }
					var hooks, renewals atomic.Int32
					h := &generationHandler{handle: func(_ Conn, m *Message) {
						m.BeginDispatch()()
						close(callbackEntered)
						if mode != 0 {
							<-callbackRelease
						}
					}}
					if stage == "retire" {
						h.retire = func(Conn, RetirementReason) error { pause(); return nil }
					} else {
						transport.reset = pause
					}
					srv := &Server{Handler: h, MaxConcurrentHandlers: mode,
						OnShutdownConnection: func(context.Context, Conn) { hooks.Add(1) },
						OnConnectionRestart:  func(Conn, Conn, RetirementReason) { renewals.Add(1) }}
					c := srv.newConn(transport)
					c.accepted = true
					if !srv.trackConn(c) {
						t.Fatal("track connection")
					}
					gone := c.writer.CloseNotify()
					observed := make(chan struct{})
					go func() { <-gone; close(observed) }()
					served := make(chan struct{})
					go func() { c.serve(); close(served) }()
					peerRead := make(chan error, 1)
					peerDone := make(chan struct{})
					go func() {
						var b [1]byte
						_, err := remote.Read(b[:])
						peerRead <- err
						close(peerDone)
					}()
					defer func() {
						unblock()
						unblockCallback()
						_ = raw.Close()
						_ = remote.Close()
						<-served
						<-peerDone
						<-observed
					}()
					raw.reads <- restartRead{data: cerPayload(t)}
					<-callbackEntered
					raw.reads <- restartRead{err: &TransportRestartError{AssociationID: 81}}
					raw.reads <- restartRead{data: cerPayload(t)}
					<-entered
					ctx := &retirementShutdownContext{Context: context.Background(), entered: make(chan struct{}), served: served}
					shutdown := make(chan error, 1)
					go func() { shutdown <- srv.Shutdown(ctx) }()
					<-ctx.entered
					unblock()
					unblockCallback()
					if err := <-shutdown; err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					if got := transport.closeCalls.Load(); got != 1 {
						t.Errorf("Shutdown closed physical transport %d times, want exactly once", got)
					}
					select {
					case err := <-peerRead:
						if !errors.Is(err, io.EOF) {
							t.Errorf("peer read after Shutdown = %v, want EOF", err)
						}
					default:
						t.Error("Shutdown left physical peer reader blocked")
					}
					select {
					case <-observed:
					default:
						t.Error("Shutdown left CloseNotify listener blocked")
					}
					if hooks.Load() != 0 || renewals.Load() != 0 {
						t.Errorf("Shutdown ran retired hook/replacement: hooks=%d renewals=%d", hooks.Load(), renewals.Load())
					}
					srv.mu.Lock()
					remaining := len(srv.conns)
					srv.mu.Unlock()
					if remaining != 0 {
						t.Errorf("Shutdown left %d tracked connections", remaining)
					}
				})
			})
		}
	}
}

func TestShutdownSkipsRetiredGenerationHook(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		var hooks atomic.Int32
		h := &generationHandler{handle: func(Conn, *Message) {}, retire: func(Conn, RetirementReason) error {
			close(entered)
			<-release
			return nil
		}}
		srv := &Server{Handler: h, OnShutdownConnection: func(context.Context, Conn) { hooks.Add(1) }}
		f := newGenerationFixture(t, srv)
		defer unblock()
		f.restart()
		<-entered
		shutdown := make(chan error, 1)
		go func() { shutdown <- srv.Shutdown(context.Background()) }()
		<-f.c.owner.shutdownDone
		synctest.Wait()
		select {
		case <-f.transport.closed:
		default:
			t.Error("Shutdown worker returned without closing retired transport")
		}
		if hooks.Load() != 0 {
			t.Errorf("OnShutdownConnection called retired generation: %d calls", hooks.Load())
		}
		unblock()
		if err := <-shutdown; err != nil {
			t.Fatal(err)
		}
	})
}

type shutdownBlockingListener struct {
	entered, release chan struct{}
}

func (*shutdownBlockingListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (*shutdownBlockingListener) Addr() net.Addr            { return &net.TCPAddr{Port: 3868} }
func (l *shutdownBlockingListener) Close() error {
	close(l.entered)
	<-l.release
	return nil
}

func TestShutdownMarksDrainingBeforeListenerClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, remote := net.Pipe()
		defer func() { _ = remote.Close() }()
		raw := &restartTransport{Conn: local, reads: make(chan restartRead, 2), closed: make(chan struct{})}
		defer func() { _ = raw.Close() }()
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		transport := &shutdownRetirementTransport{fencedMultistream: &fencedMultistream{Conn: raw}, reset: func() { close(entered); <-release }}
		var renewals atomic.Int32
		callbackEntered, callbackRelease := make(chan struct{}), make(chan struct{})
		var callbackOnce sync.Once
		unblockCallback := func() { callbackOnce.Do(func() { close(callbackRelease) }) }
		defer unblockCallback()
		listener := &shutdownBlockingListener{entered: make(chan struct{}), release: make(chan struct{})}
		var listenerOnce sync.Once
		unblockListener := func() { listenerOnce.Do(func() { close(listener.release) }) }
		defer unblockListener()
		srv := &Server{MaxConcurrentHandlers: -1, Handler: &generationHandler{handle: func(_ Conn, m *Message) {
			m.BeginDispatch()()
			close(callbackEntered)
			<-callbackRelease
		}},
			OnConnectionRestart: func(Conn, Conn, RetirementReason) { renewals.Add(1) },
			listeners:           map[net.Listener]struct{}{listener: {}}}
		c := srv.newConn(transport)
		c.accepted = true
		if !srv.trackConn(c) {
			t.Fatal("track connection")
		}
		served := make(chan struct{})
		go func() { c.serve(); close(served) }()
		raw.reads <- restartRead{data: cerPayload(t)}
		<-callbackEntered
		raw.reads <- restartRead{err: &TransportRestartError{AssociationID: 81}}
		<-entered
		shutdown := make(chan error, 1)
		go func() { shutdown <- srv.Shutdown(context.Background()) }()
		<-listener.entered
		unblock()
		synctest.Wait()
		if renewals.Load() != 0 {
			t.Error("Shutdown allowed renewal while listener Close was blocked")
		}
		if transport.closeCalls.Load() != 1 {
			t.Error("Shutdown abandonment left transport open behind active callback")
		}
		unblockCallback()
		unblockListener()
		if err := <-shutdown; err != nil {
			t.Fatal(err)
		}
		<-served
		if got := transport.closeCalls.Load(); got != 1 {
			t.Errorf("Shutdown closed physical transport %d times, want exactly once", got)
		}
	})
}

func TestServeExitClosesRetiredPhysicalOwner(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	raw := &restartTransport{Conn: local, reads: make(chan restartRead), closed: make(chan struct{})}
	defer func() { _ = raw.Close() }()
	close(raw.reads)
	transport := &shutdownRetirementTransport{fencedMultistream: &fencedMultistream{Conn: raw}}
	srv := &Server{}
	c := srv.newConn(transport)
	c.accepted = true
	if !srv.trackConn(c) {
		t.Fatal("track connection")
	}
	// Reader finalization owns the physical transport even if renewal has
	// already fenced this generation and cannot publish a replacement.
	c.retirement.Store(uint32(SCTPAssociationRestart))
	c.closed.Store(true)
	c.serve()
	if got := transport.closeCalls.Load(); got != 1 {
		t.Errorf("retired reader exit closed physical transport %d times, want exactly once", got)
	}
	select {
	case <-c.writer.CloseNotify():
	default:
		t.Error("retired reader exit left CloseNotify open")
	}
	srv.mu.Lock()
	remaining := len(srv.conns)
	srv.mu.Unlock()
	if remaining != 0 {
		t.Errorf("retired reader exit left %d tracked connections", remaining)
	}
}

func TestShutdownRetirementWithActiveCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		callbackEntered, retireEntered := make(chan struct{}), make(chan struct{})
		callbackRelease, retireRelease := make(chan struct{}), make(chan struct{})
		var callbackOnce, retireOnce sync.Once
		unblockCallback := func() { callbackOnce.Do(func() { close(callbackRelease) }) }
		unblockRetire := func() { retireOnce.Do(func() { close(retireRelease) }) }
		var hooks, renewals atomic.Int32
		srv := &Server{MaxConcurrentHandlers: -1,
			Handler: &generationHandler{handle: func(_ Conn, m *Message) {
				m.BeginDispatch()()
				close(callbackEntered)
				<-callbackRelease
			}, retire: func(Conn, RetirementReason) error {
				close(retireEntered)
				<-retireRelease
				return nil
			}},
			OnShutdownConnection: func(context.Context, Conn) { hooks.Add(1) },
			OnConnectionRestart:  func(Conn, Conn, RetirementReason) { renewals.Add(1) }}
		f := newGenerationFixture(t, srv)
		defer unblockCallback()
		defer unblockRetire()
		f.send(t, generationCER(t))
		<-callbackEntered
		f.restart()
		<-retireEntered
		shutdown := make(chan error, 1)
		go func() { shutdown <- srv.Shutdown(context.Background()) }()
		synctest.Wait()
		select {
		case <-f.transport.closed:
		default:
			t.Error("Shutdown left retired socket open behind active callback and retirement hook")
		}
		unblockRetire()
		unblockCallback()
		if err := <-shutdown; err != nil {
			t.Fatal(err)
		}
		if hooks.Load() != 0 || renewals.Load() != 0 {
			t.Errorf("Shutdown ran retired hook/replacement: hooks=%d renewals=%d", hooks.Load(), renewals.Load())
		}
	})
}
