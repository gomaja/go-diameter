package diam

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type generationHandler struct {
	accept   func(Conn) func()
	retire   func(Conn, RetirementReason) error
	eligible func(Conn) bool
	handle   func(Conn, *Message)
}

func (h *generationHandler) ServeDIAM(c Conn, m *Message) { h.handle(c, m) }
func (h *generationHandler) HandleAccept(c Conn) func() {
	if h.accept != nil {
		return h.accept(c)
	}
	return nil
}
func (h *generationHandler) HandleRetire(c Conn, r RetirementReason) error {
	if h.retire != nil {
		return h.retire(c, r)
	}
	return nil
}
func (h *generationHandler) CanRenewAcceptedCER(c Conn) bool {
	return h.eligible != nil && h.eligible(c)
}

type generationFixture struct {
	c         *conn
	transport *restartTransport
	peer      net.Conn
	finished  chan struct{}
}

func newGenerationFixture(t *testing.T, srv *Server) *generationFixture {
	t.Helper()
	local, remote := net.Pipe()
	f := &generationFixture{transport: &restartTransport{Conn: local, reads: make(chan restartRead, 16), closed: make(chan struct{})}, peer: remote, finished: make(chan struct{})}
	f.c = srv.newConn(f.transport)
	f.c.accepted = true
	if !srv.trackConn(f.c) {
		t.Fatal("track connection")
	}
	go func() { f.c.serve(); close(f.finished) }()
	t.Cleanup(func() { close(f.transport.reads); _ = f.peer.Close(); <-f.finished })
	return f
}
func (f *generationFixture) send(t *testing.T, m *Message) {
	t.Helper()
	b, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	f.transport.reads <- restartRead{data: b}
}
func (f *generationFixture) answer(t *testing.T) *Message {
	t.Helper()
	if err := f.peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	m, err := ReadMessage(f.peer, nil)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}
	return m
}
func (f *generationFixture) restart() {
	f.transport.reads <- restartRead{err: &TransportRestartError{AssociationID: 7, InboundStreams: 8, OutboundStreams: 8}}
}
func generationCER(t *testing.T) *Message {
	t.Helper()
	m, err := ReadMessage(bytes.NewReader(cerPayload(t)), nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func awaitGeneration(t *testing.T, c <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(3 * time.Second):
		t.Fatal(what)
	}
}

type tlsRestartTransport struct {
	net.Conn
	restart, seen atomic.Bool
	staleWrites   atomic.Int32
	closed        chan struct{}
	closeOnce     sync.Once
}

func (c *tlsRestartTransport) Read(b []byte) (int, error) {
	if c.restart.Swap(false) {
		c.seen.Store(true)
		return 0, &TransportRestartError{AssociationID: 42}
	}
	return c.Conn.Read(b)
}

func (c *tlsRestartTransport) Write(b []byte) (int, error) {
	if c.seen.Load() {
		c.staleWrites.Add(1)
	}
	return c.Conn.Write(b)
}

func (c *tlsRestartTransport) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type tlsAcceptHandler struct{ accept func(Conn) func() }

func (h tlsAcceptHandler) ServeDIAM(Conn, *Message)   {}
func (h tlsAcceptHandler) HandleAccept(c Conn) func() { return h.accept(c) }

type tlsRestartLog struct {
	slog.Handler
	entered, release chan struct{}
}

func (h *tlsRestartLog) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "diam: transport restart without retirement handler; closing connection" {
		close(h.entered)
		<-h.release
	}
	return h.Handler.Handle(ctx, r)
}

func generationCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestAcceptedTLSRestartClosesPhysical(t *testing.T) {
	for _, mode := range []string{"retirement", "custom", "retired-busy", "close-race"} {
		t.Run(mode, func(t *testing.T) { testAcceptedTLSRestartClosesPhysical(t, mode) })
	}
}

func testAcceptedTLSRestartClosesPhysical(t *testing.T, mode string) {
	t.Helper()
	cert := generationCertificate(t)
	local, remote := net.Pipe()
	raw := &tlsRestartTransport{Conn: local, closed: make(chan struct{})}
	var accepts, restarts atomic.Int32
	accept := func(c Conn) func() {
		if accepts.Add(1) > 1 {
			c.Close()
			return nil
		}
		if c.TLS() == nil {
			t.Error("acceptance before TLS handshake")
		}
		raw.restart.Store(true)
		return nil
	}
	var h Handler = &generationHandler{accept: accept}
	if mode == "custom" || mode == "close-race" {
		h = tlsAcceptHandler{accept: accept}
	}
	srv := &Server{Handler: h, OnConnectionRestart: func(Conn, Conn, RetirementReason) { restarts.Add(1) }}
	var logger *tlsRestartLog
	var releaseOnce sync.Once
	releaseLog := func() {
		if logger != nil {
			releaseOnce.Do(func() { close(logger.release) })
		}
	}
	if mode == "close-race" {
		logger = &tlsRestartLog{Handler: slog.NewTextHandler(io.Discard, nil), entered: make(chan struct{}), release: make(chan struct{})}
		srv.Logger = slog.New(logger)
	}
	c := srv.newConn(tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}))
	c.accepted = true
	var retiredDone chan struct{}
	if mode == "retired-busy" {
		retiredDone = make(chan struct{})
		c.owner.retired = &conn{done: retiredDone}
	}
	finished := make(chan struct{})
	var closeDone chan struct{}
	go func() { c.serve(); close(finished) }()
	client := tls.Client(remote, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	t.Cleanup(func() {
		_ = remote.Close()
		_ = raw.Close()
		if retiredDone != nil {
			close(retiredDone)
		}
		releaseLog()
		<-finished
		if closeDone != nil {
			<-closeDone
		}
	})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if logger != nil {
		awaitGeneration(t, logger.entered, "TLS restart fallback did not reach close gate")
		closeDone = make(chan struct{})
		go func() { c.writer.Close(); close(closeDone) }()
	}
	awaitGeneration(t, raw.closed, "TLS restart did not close physical transport")
	releaseLog()
	if mode == "retired-busy" {
		// Final Server cleanup waits for the already retired generation.
		close(retiredDone)
		retiredDone = nil
	}
	awaitGeneration(t, finished, "TLS restart did not close physical connection")
	if raw.staleWrites.Load() != 0 {
		t.Fatalf("TLS restart wrote %d records from old session", raw.staleWrites.Load())
	}
	if accepts.Load() != 1 || restarts.Load() != 0 {
		t.Fatalf("cached TLS restart created replacement: accepts=%d restarts=%d", accepts.Load(), restarts.Load())
	}
	if !c.writer.Closed() {
		t.Fatal("TLS restart retained live connection")
	}
}

func TestAcceptedTLSCERRenewal(t *testing.T) {
	cert := generationCertificate(t)
	local, remote := net.Pipe()
	conns := make(chan Conn, 2)
	type admittedKey struct{}
	h := &generationHandler{eligible: func(c Conn) bool { return c.Context().Value(admittedKey{}) == true }, handle: func(c Conn, m *Message) {
		release := m.BeginDispatch()
		defer release()
		c.SetContext(context.WithValue(c.Context(), admittedKey{}, true))
		conns <- c
		_, _ = m.Answer(Success).WriteTo(c)
	}}
	srv := &Server{Handler: h, RenewAcceptedCER: true, MaxConcurrentHandlers: 2}
	c := srv.newConn(tls.Server(local, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}))
	c.accepted = true
	finished := make(chan struct{})
	go func() { c.serve(); close(finished) }()
	client := tls.Client(remote, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	t.Cleanup(func() { _ = remote.Close(); <-finished })
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := generationCER(t).WriteTo(client); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadMessage(client, nil); err != nil {
			t.Fatalf("TLS CER %d: %v", i+1, err)
		}
	}
	old, next := <-conns, <-conns
	if old == next || !old.Closed() || next.Closed() || next.TLS() == nil {
		t.Fatal("healthy TLS CER renewal did not preserve transport and change generation")
	}
}

func TestAcceptedGenerationIndependentDispatchAndHooks(t *testing.T) {
	for _, mode := range []int{2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			var accepts, cleanups, physical atomic.Int32
			var connsMu sync.Mutex
			var conns []Conn
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			type contextKey struct{}
			h := &generationHandler{accept: func(c Conn) func() { accepts.Add(1); return func() { cleanups.Add(1) } }, handle: func(c Conn, m *Message) {
				releaseAdmission := m.BeginDispatch()
				if m.Header.CommandCode == DeviceWatchdog {
					releaseAdmission()
					close(entered)
					<-release
					return
				}
				defer releaseAdmission()
				connsMu.Lock()
				conns = append(conns, c)
				connsMu.Unlock()
				c.SetContext(context.WithValue(c.Context(), contextKey{}, c))
				_, _ = m.Answer(Success).WriteTo(c)
			}}
			renewed := make(chan struct{})
			srv := &Server{Handler: unwrapHandler{unwrapHandler{h}}, MaxConcurrentHandlers: mode, OnNewConnection: func(Conn) { physical.Add(1) }, OnConnectionRestart: func(old, next Conn, r RetirementReason) {
				if r != SCTPAssociationRestart || old == next {
					t.Error("restart hook identities/reason")
				}
				if next.Context().Value(contextKey{}) != nil {
					t.Error("new context inherited old value")
				}
				if old.Context().Value(contextKey{}) != old {
					t.Error("old context lost value")
				}
				if !old.Closed() || next.Closed() {
					t.Error("generation close flags")
				}
				select {
				case <-mustConnAs[CloseNotifier](t, old).CloseNotify():
				default:
					t.Error("old CloseNotify open")
				}
				select {
				case <-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, old).DispatchDone():
					t.Error("old DispatchDone closed during callback")
				default:
				}
				close(renewed)
			}}
			f := newGenerationFixture(t, srv)
			defer unblock()
			f.send(t, generationCER(t))
			f.answer(t)
			f.send(t, NewRequest(DeviceWatchdog, 0, nil))
			awaitGeneration(t, entered, "application not entered")
			f.restart()
			f.send(t, generationCER(t))
			f.answer(t)
			awaitGeneration(t, renewed, "restart hook")
			connsMu.Lock()
			old, next := conns[0], conns[1]
			connsMu.Unlock()
			if accepts.Load() != 2 || cleanups.Load() != 1 || physical.Load() != 1 {
				t.Fatalf("hooks accept=%d cleanup=%d physical=%d", accepts.Load(), cleanups.Load(), physical.Load())
			}
			if l := mustConnAs[ConnLifecycle](t, unwrapConn{next}); l.Generation() != 2 || l.RetirementReason() != 0 {
				t.Fatal("new lifecycle")
			}
			if l := mustConnAs[ConnLifecycle](t, old); l.Generation() != 1 || l.RetirementReason() != SCTPAssociationRestart {
				t.Fatal("old lifecycle")
			}
			if _, err := old.WriteStream([]byte("stale"), 3); !errors.Is(err, ErrConnectionRetired) {
				t.Fatalf("old stream write %v", err)
			}
			old.Close()
			if next.Closed() {
				t.Fatal("old Close reached new generation")
			}
			unblock()
			awaitGeneration(t, mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, old).DispatchDone(), "old dispatch not done")
			select {
			case <-mustConnAs[CloseNotifier](t, next).CloseNotify():
				t.Fatal("new CloseNotify inherited closure")
			default:
			}
			next.Close()
			awaitGeneration(t, f.finished, "physical teardown not finished")
			if accepts.Load() != 2 || cleanups.Load() != 2 || physical.Load() != 1 {
				t.Fatalf("final hooks accepts=%d cleanups=%d physical=%d", accepts.Load(), cleanups.Load(), physical.Load())
			}
		})
	}
}

func TestRestartDiscardsInterruptedMessage(t *testing.T) {
	for _, offset := range []int{7, 25} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			seen := make(chan Conn, 2)
			srv := &Server{Handler: &generationHandler{handle: func(c Conn, m *Message) {
				release := m.BeginDispatch()
				defer release()
				seen <- c
				_, _ = m.Answer(Success).WriteTo(c)
			}}}
			f := newGenerationFixture(t, srv)
			f.send(t, generationCER(t))
			f.answer(t)
			<-seen
			f.transport.reads <- restartRead{data: cerPayload(t)[:offset]}
			f.restart()
			f.send(t, generationCER(t))
			f.answer(t)
			if c := <-seen; mustConnAs[ConnLifecycle](t, c).Generation() != 2 {
				t.Fatal("partial input retained generation")
			}
		})
	}
}

func TestCERGenerationKeepsReadAhead(t *testing.T) {
	var calls atomic.Int32
	// Leave room for a replay so a failed reply check can drain the reader.
	seen := make(chan Conn, 4)
	type admittedKey struct{}
	srv := &Server{RenewAcceptedCER: true, Handler: &generationHandler{eligible: func(c Conn) bool { return c.Context().Value(admittedKey{}) != nil }, handle: func(c Conn, m *Message) {
		release := m.BeginDispatch()
		defer release()
		seen <- c
		if m.Header.CommandCode == CapabilitiesExchange {
			c.SetContext(context.WithValue(c.Context(), admittedKey{}, true))
		}
		calls.Add(1)
		_, _ = m.Answer(Success).WriteTo(c)
	}}}
	f := newGenerationFixture(t, srv)
	// One underlying Read provides two CERs and subsequent application input.
	requests := []*Message{generationCER(t), generationCER(t), NewRequest(DeviceWatchdog, 0, nil)}
	var data []byte
	for i, m := range requests {
		m.Header.HopByHopID = 0x81000001 + uint32(i)
		m.Header.EndToEndID = 0x82000001 + uint32(i)
		b, err := m.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, b...)
	}
	f.transport.reads <- restartRead{data: data}
	for i, request := range requests {
		answer := f.answer(t)
		if answer.Header.CommandFlags&RequestFlag != 0 || answer.Header.CommandCode != request.Header.CommandCode ||
			answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID {
			t.Fatalf("answer %d is not for expected CER/CER/DWR", i)
		}
	}
	first, next, last := <-seen, <-seen, <-seen
	if first == next || next != last || calls.Load() != 3 {
		t.Fatal("triggering CER/read-ahead dispatch")
	}
}

func TestRestartWithoutRetirementHandlerCloses(t *testing.T) {
	srv := &Server{Handler: HandlerFunc(func(c Conn, m *Message) { _, _ = m.Answer(Success).WriteTo(c) })}
	f := newGenerationFixture(t, srv)
	f.send(t, generationCER(t))
	f.answer(t)
	f.restart()
	awaitGeneration(t, f.c.writer.CloseNotify(), "unsupported handler retained physical connection")
	if !f.c.writer.Closed() {
		t.Fatal("unsupported handler still open")
	}
}

func TestRestartAdmissionTimeoutCloses(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	srv := &Server{MaxConcurrentHandlers: -1, Handler: &generationHandler{handle: func(Conn, *Message) { close(entered); <-release }}}
	f := newGenerationFixture(t, srv)
	defer unblock()
	f.send(t, generationCER(t))
	awaitGeneration(t, entered, "blocked admission not entered")
	f.restart()
	awaitGeneration(t, f.c.writer.CloseNotify(), "retirement CloseNotify")
	// Retirement fails rather than allowing a later CER to bypass admission.
	if err := f.peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("retirement timeout retained physical socket")
	}
	unblock()
}

func TestRetirementFailureNeverCreatesGeneration(t *testing.T) {
	for _, failure := range []string{"error", "panic", "timeout"} {
		t.Run(failure, func(t *testing.T) {
			var renewals atomic.Int32
			release := make(chan struct{})
			defer close(release)
			srv := &Server{OnConnectionRestart: func(Conn, Conn, RetirementReason) { renewals.Add(1) }, Handler: &generationHandler{handle: func(c Conn, m *Message) { _, _ = m.Answer(Success).WriteTo(c) }, retire: func(Conn, RetirementReason) error {
				switch failure {
				case "error":
					return errors.New("refused")
				case "panic":
					panic("retirement")
				default:
					<-release
					return nil
				}
			}}}
			f := newGenerationFixture(t, srv)
			f.send(t, generationCER(t))
			f.answer(t)
			f.restart()
			if err := f.peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatal("retirement failure retained physical socket")
			}
			if renewals.Load() != 0 {
				t.Fatal("retirement failure allocated replacement")
			}
		})
	}
}

type fencedMultistream struct {
	net.Conn
	writerStream atomic.Uint64
	setters      atomic.Int32
	entered      chan struct{}
	once         sync.Once
}

func (c *fencedMultistream) Write(b []byte) (int, error) {
	if c.entered != nil {
		c.once.Do(func() { close(c.entered) })
	}
	return c.Conn.Write(b)
}
func (c *fencedMultistream) WriteStream(b []byte, _ uint) (int, error) { return c.Write(b) }
func (c *fencedMultistream) ReadAny(b []byte) (int, uint, error) {
	n, err := c.Read(b)
	return n, 0, err
}
func (c *fencedMultistream) ReadStream(b []byte, _ uint) (int, error) { return c.Read(b) }
func (c *fencedMultistream) ReadAtLeast(b []byte, n int, _ uint) (int, uint, error) {
	read, err := io.ReadAtLeast(c, b, n)
	return read, 0, err
}
func (c *fencedMultistream) CurrentStream() uint        { return 0 }
func (c *fencedMultistream) ResetCurrentStream()        {}
func (c *fencedMultistream) SetCurrentStream(uint) uint { return 0 }
func (c *fencedMultistream) CurrentWriterStream() uint  { return uint(c.writerStream.Load()) }
func (c *fencedMultistream) ResetWriterStream()         { c.setters.Add(1); c.writerStream.Store(0) }
func (c *fencedMultistream) SetWriterStream(s uint) uint {
	c.setters.Add(1)
	return uint(c.writerStream.Swap(uint64(s)))
}
func (c *fencedMultistream) SetErrorHandler(MutistreamConnErrorHandler) {}

func TestRetiredStreamSettersAreFenced(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = remote.Close(); _ = local.Close() }()
	transport := &fencedMultistream{Conn: local}
	srv := &Server{Handler: &generationHandler{}}
	c := srv.newConn(transport)
	c.accepted = true
	c.writer.SetWriterStream(3)
	next := c.renew(SCTPAssociationRestart, &TransportRestartError{})
	if next == nil {
		t.Fatal("renewal failed")
	}
	before := transport.setters.Load()
	c.writer.SetWriterStream(9)
	c.writer.ResetWriterStream()
	if transport.setters.Load() != before || next.writer.CurrentWriterStream() != 3 {
		t.Fatal("retired setter changed transport")
	}
	if c.writer.Connection() != transport || next.writer.Connection() != transport {
		t.Fatal("raw Connection compatibility")
	}
}

func TestRetirementQuiescesInflightSCTPWrite(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = remote.Close(); _ = local.Close() }()
	transport := &fencedMultistream{Conn: local, entered: make(chan struct{})}
	srv := &Server{Handler: &generationHandler{}}
	c := srv.newConn(transport)
	c.accepted = true
	written := make(chan error, 1)
	go func() { _, err := c.writer.Write([]byte("old")); written <- err }()
	awaitGeneration(t, transport.entered, "write not started")
	next := c.renew(SCTPAssociationRestart, &TransportRestartError{})
	if next == nil {
		t.Fatal("write quiescence failed")
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("blocked write not interrupted")
		}
	case <-time.After(time.Second):
		t.Fatal("inflight write remains")
	}
	go func() { _, err := next.writer.Write([]byte("new")); written <- err }()
	b := make([]byte, 3)
	if _, err := io.ReadFull(remote, b); err != nil || string(b) != "new" {
		t.Fatalf("new write %q: %v", b, err)
	}
	if err := <-written; err != nil {
		t.Fatalf("write deadline not cleared: %v", err)
	}
}

func TestRetirementPartialTCPWriteCloses(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = remote.Close(); _ = local.Close() }()
	srv := &Server{Handler: &generationHandler{}}
	c := srv.newConn(local)
	c.accepted = true
	written := make(chan error, 1)
	go func() { _, err := c.writer.Write([]byte("old frame")); written <- err }()
	b := make([]byte, 1)
	if _, err := remote.Read(b); err != nil {
		t.Fatal(err)
	}
	if next := c.renew(AcceptedCERRenewal, nil); next != nil {
		t.Fatal("partial TCP frame spliced into replacement")
	}
	if err := <-written; err == nil {
		t.Fatal("partial write not interrupted")
	}
	if _, err := remote.Read(b); err == nil {
		t.Fatal("physical socket still open")
	}
	awaitGeneration(t, c.writer.CloseNotify(), "partial write did not notify owners")
}

type ignoringWriteDeadline struct {
	net.Conn
	entered, release chan struct{}
}

func (c *ignoringWriteDeadline) SetWriteDeadline(time.Time) error { return nil }
func (c *ignoringWriteDeadline) Write([]byte) (int, error) {
	close(c.entered)
	<-c.release
	return 0, net.ErrClosed
}
func TestRetirementWriteTimeoutCloses(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = remote.Close(); _ = local.Close() }()
	transport := &ignoringWriteDeadline{Conn: local, entered: make(chan struct{}), release: make(chan struct{})}
	srv := &Server{Handler: &generationHandler{}}
	c := srv.newConn(transport)
	c.accepted = true
	written := make(chan error, 1)
	go func() { _, err := c.writer.Write([]byte("old")); written <- err }()
	awaitGeneration(t, transport.entered, "write not started")
	if next := c.renew(SCTPAssociationRestart, &TransportRestartError{}); next != nil {
		t.Fatal("unquiesced write got replacement")
	}
	close(transport.release)
	if err := <-written; err == nil {
		t.Fatal("writer error missing")
	}
	if _, err := remote.Read(make([]byte, 1)); err == nil {
		t.Fatal("quiescence timeout did not close socket")
	}
}

func TestSecondRestartWithOutstandingGenerationCloses(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = remote.Close(); _ = local.Close() }()
	entered, release := make(chan struct{}), make(chan struct{})
	srv := &Server{MaxConcurrentHandlers: -1, Handler: &generationHandler{handle: func(_ Conn, m *Message) {
		m.BeginDispatch()()
		close(entered)
		<-release
	}}}
	c := srv.newConn(local)
	c.accepted = true
	c.dispatch(generationCER(t))
	awaitGeneration(t, entered, "old callback did not enter")
	defer func() { close(release); c.hwg.Wait() }()
	next := c.renew(SCTPAssociationRestart, &TransportRestartError{})
	if next == nil {
		t.Fatal("first restart failed")
	}
	if third := next.renew(SCTPAssociationRestart, &TransportRestartError{}); third != nil {
		t.Fatal("unbounded retired generations")
	}
	if !next.writer.Closed() {
		t.Fatal("repeat restart retained physical owner")
	}
}

func TestRenewalHookPanicsClosePhysicalOwner(t *testing.T) {
	for _, hook := range []string{"accept", "restart", "cleanup"} {
		t.Run(hook, func(t *testing.T) {
			var accepts atomic.Int32
			h := &generationHandler{accept: func(Conn) func() {
				if accepts.Add(1) == 2 && hook == "accept" {
					panic("accept")
				}
				return func() {
					if hook == "cleanup" {
						panic("cleanup")
					}
				}
			}, handle: func(c Conn, m *Message) { _, _ = m.Answer(Success).WriteTo(c) }}
			srv := &Server{Handler: h, OnConnectionRestart: func(Conn, Conn, RetirementReason) {
				if hook == "restart" {
					panic("restart")
				}
			}}
			f := newGenerationFixture(t, srv)
			f.send(t, generationCER(t))
			f.answer(t)
			f.restart()
			if err := f.peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatal("hook panic retained physical socket")
			}
		})
	}
}

func TestRenewalHasFreshDispatchSlots(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	srv := &Server{MaxConcurrentHandlers: 2, Handler: &generationHandler{handle: func(c Conn, m *Message) {
		admission := m.BeginDispatch()
		defer admission()
		if m.Header.CommandCode == DeviceWatchdog {
			admission()
			entered <- struct{}{}
			<-release
			return
		}
		_, _ = m.Answer(Success).WriteTo(c)
	}}}
	f := newGenerationFixture(t, srv)
	defer unblock()
	f.send(t, generationCER(t))
	f.answer(t)
	for range 2 {
		f.send(t, NewRequest(DeviceWatchdog, 0, nil))
		awaitGeneration(t, entered, "old application slot")
	}
	f.restart()
	f.send(t, generationCER(t))
	f.answer(t)
	select {
	case <-f.c.done:
		t.Fatal("old callback accounting lost")
	default:
	}
	unblock()
	awaitGeneration(t, f.c.done, "old dispatch not done")
}

func TestShutdownClosesDuringRetirement(t *testing.T) {
	entered, release, shutdownHook := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var renewals atomic.Int32
	h := &generationHandler{handle: func(c Conn, m *Message) { _, _ = m.Answer(Success).WriteTo(c) }, retire: func(Conn, RetirementReason) error { close(entered); <-release; return nil }}
	srv := &Server{Handler: h, OnConnectionRestart: func(Conn, Conn, RetirementReason) { renewals.Add(1) }, OnShutdownConnection: func(context.Context, Conn) { close(shutdownHook) }}
	f := newGenerationFixture(t, srv)
	defer unblock()
	f.send(t, generationCER(t))
	f.answer(t)
	f.restart()
	awaitGeneration(t, entered, "retirement not entered")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	shutdown := make(chan error, 1)
	go func() { shutdown <- srv.Shutdown(ctx) }()
	awaitGeneration(t, f.c.owner.shutdownDone, "retired shutdown worker did not finish")
	select {
	case <-shutdownHook:
		t.Fatal("shutdown hook ran on retired generation")
	default:
	}
	awaitGeneration(t, f.transport.closed, "shutdown left physical connection open")
	unblock()
	if err := <-shutdown; err != nil {
		t.Fatal(err)
	}
	if renewals.Load() != 0 {
		t.Fatal("shutdown allowed replacement")
	}
	awaitGeneration(t, f.finished, "physical reader not drained")
}
