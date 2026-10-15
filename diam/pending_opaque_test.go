package diam

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// The transport does not expose progress. Its first Write remains blocked
// until Closing has latched, before forwarding any bytes to TCP.
type pendingOpaqueTransport struct {
	net.Conn
	entered, release chan struct{}
	fail             bool
	calls            int
}

type pendingOpaqueFlushGate struct {
	writer           io.Writer
	entered, release chan struct{}
	once             sync.Once
}

func (w *pendingOpaqueFlushGate) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return w.writer.Write(b)
}

func TestPendingRequestGateAdmissionKeepsControlWriter(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	dialed := make(chan net.Conn, 1)
	go func() { conn, _ := net.Dial("tcp", listener.Addr().String()); dialed <- conn }()
	raw, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	peer := <-dialed
	defer func() { _ = peer.Close() }()
	transport := &pendingOpaqueTransport{Conn: raw, entered: make(chan struct{}), release: make(chan struct{})}
	close(transport.release)
	c := (&Server{}).newConn(transport)
	defer c.writer.Close()
	requests := c.writer.PendingRequests()
	first := NewRequest(999, 42, dict.Default)
	if _, err := first.WriteTo(c.writer); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMessage(peer, dict.Default); err != nil {
		t.Fatal(err)
	}
	gate := &pendingOpaqueFlushGate{writer: c.rwc, entered: make(chan struct{}), release: make(chan struct{})}
	c.buf.Writer = bufio.NewWriter(gate)
	second := NewRequest(999, 42, dict.Default)
	result := make(chan error, 1)
	go func() { _, err := second.WriteTo(c.writer); result <- err }()
	<-gate.entered // The write gate is owned; transport progress has not started.
	requests.CloseAdmission()
	if !requests.MatchAnswer(first.Answer(Success), false) || !requests.MatchAnswer(second.Answer(Success), false) {
		t.Error("request holding the write gate before Closing lost answer ownership")
	}
	close(gate.release)
	if err := <-result; err != nil {
		t.Fatalf("admitted writer=%v", err)
	}
	if decoded, err := ReadMessage(peer, dict.Default); err != nil || decoded.Header.HopByHopID != second.Header.HopByHopID {
		t.Fatalf("admitted request wire=%v err=%v", decoded, err)
	}
	if c.owner.writeFailed.Load() {
		t.Error("admitted writer poisoned the transport")
	}
	dpa := NewMessage(DisconnectPeer, 0, 0, 101, 102, dict.Default)
	dpa.AddAVP(NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(Success)))
	dpa.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("local.example")))
	dpa.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	if _, err := dpa.WriteTo(c.writer); err != nil {
		t.Fatalf("admitted request prevented DPA: %v", err)
	}
	decoded, err := ReadMessage(peer, dict.Default)
	if err != nil || decoded.Header.CommandCode != DisconnectPeer || decoded.Header.HopByHopID != 101 {
		t.Fatalf("DPA wire=%v err=%v", decoded, err)
	}
	if !requests.MatchAnswer(first.Answer(Success), true) || !requests.MatchAnswer(second.Answer(Success), true) || requests.HasPending() {
		t.Error("gate admission lost or polluted the sent drain set")
	}
}

func (c *pendingOpaqueTransport) Write(b []byte) (int, error) {
	c.calls++
	if c.calls == 1 {
		close(c.entered)
		<-c.release
		if c.fail {
			return 0, pendingWriteTimeout{}
		}
	}
	return c.Conn.Write(b)
}

func TestPendingRequestOpaqueWriteClosingWire(t *testing.T) {
	for _, retries := range []uint{0, 1} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("retries=%d/error=%t", retries, fail), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = listener.Close() }()
				dialed := make(chan net.Conn, 1)
				go func() { conn, _ := net.Dial("tcp", listener.Addr().String()); dialed <- conn }()
				raw, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				peer := <-dialed
				defer func() { _ = peer.Close() }()
				transport := &pendingOpaqueTransport{Conn: raw, entered: make(chan struct{}), release: make(chan struct{}), fail: fail}
				c := (&Server{}).newConn(transport)
				defer c.writer.Close()
				requests := c.writer.PendingRequests()
				request := NewRequest(999, 42, dict.Default)
				result := make(chan error, 1)
				go func() { _, err := request.WriteToWithRetry(c.writer, retries); result <- err }()
				<-transport.entered
				closing := make(chan struct{})
				go func() { requests.CloseAdmission(); close(closing) }()
				select {
				case <-closing:
				case <-time.After(time.Second):
					close(transport.release)
					<-result
					t.Fatal("opaque Write blocked the Closing latch")
				}
				if !requests.HasPending() || !requests.MatchAnswer(request.Answer(Success), false) {
					t.Error("opaque write begun before Closing was not in flight")
				}
				close(transport.release)
				err = <-result
				if fail {
					var timeout net.Error
					if !errors.Is(err, ErrConnectionClosing) && (!errors.As(err, &timeout) || !timeout.Timeout()) {
						t.Errorf("opaque failure=%v", err)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
						t.Fatal(err)
					}
					decoded, err := ReadMessage(peer, dict.Default)
					if err != nil || decoded.Header.HopByHopID != request.Header.HopByHopID {
						t.Fatalf("opaque request wire=%v err=%v", decoded, err)
					}
				}
				if !requests.HasPending() || !requests.MatchAnswer(request.Answer(Success), true) {
					t.Error("opaque write outcome lost ownership of a possibly sent request")
				}
				if requests.MatchAnswer(request.Answer(Success), true) || requests.HasPending() {
					t.Error("opaque answer was not consumed exactly once")
				}
				later := NewRequest(999, 42, dict.Default)
				if _, err := later.WriteToWithRetry(c.writer, retries); !errors.Is(err, ErrConnectionClosing) {
					t.Errorf("post-Closing write=%v", err)
				}
				if requests.MatchAnswer(later.Answer(Success), false) {
					t.Error("post-Closing write gained answer ownership")
				}
				if err := peer.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				var b [1]byte
				if n, err := peer.Read(b[:]); n > 0 {
					t.Errorf("post-Closing request reached wire: bytes=%d err=%v", n, err)
				}
			})
		}
	}
}

func TestPendingRequestCachedErrorPreservesGateOwnership(t *testing.T) {
	raw, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	transport := &pendingOpaqueTransport{Conn: raw, entered: make(chan struct{}), release: make(chan struct{}), fail: true}
	close(transport.release)
	c := (&Server{}).newConn(transport)
	defer c.writer.Close()
	requests := c.writer.PendingRequests()
	first, second := NewRequest(999, 42, dict.Default), NewRequest(999, 42, dict.Default)
	if _, err := first.WriteTo(c.writer); err == nil {
		t.Fatal("first opaque Write did not fail")
	}
	if _, err := second.WriteTo(c.writer); err == nil {
		t.Fatal("buffered write did not retain its transport error")
	}
	if transport.calls != 1 {
		t.Fatalf("cached failure invoked opaque Write again: calls=%d", transport.calls)
	}
	requests.CloseAdmission()
	if !requests.MatchAnswer(second.Answer(Success), true) {
		t.Error("request admitted at the write gate lost ownership after cached error")
	}
	if !requests.MatchAnswer(first.Answer(Success), true) {
		t.Error("actual opaque Write lost its possible in-flight request")
	}
	if requests.HasPending() {
		t.Error("unstarted second write retained ownership")
	}
}
