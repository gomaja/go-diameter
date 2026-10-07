// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/logtest"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

var _ MessageErrorHandler = (*recordingMessageErrorHandler)(nil)

type recordingMessageErrorHandler struct {
	messages      chan *Message
	messageErrors chan *MessageError
	records       *logtest.Recorder
	handleErr     error
}

func newRecordingMessageErrorHandler() *recordingMessageErrorHandler {
	return &recordingMessageErrorHandler{
		messages:      make(chan *Message, 1),
		messageErrors: make(chan *MessageError, 1),
		records:       logtest.New(),
	}
}

func (h *recordingMessageErrorHandler) ServeDIAM(_ Conn, m *Message) {
	h.messages <- m
}

func (h *recordingMessageErrorHandler) HandleMessageError(_ Conn, _ *Message, err *MessageError) error {
	h.messageErrors <- err
	return h.handleErr
}

func TestServerContinuesAfterHandledNonFatalMessageError(t *testing.T) {
	handler := newRecordingMessageErrorHandler()
	remote, done := startPipeServer(t, handler, handler.records)
	defer closePipeServer(t, remote, done)

	malformed := testFramedMessage(t, RequestFlag, []byte{
		0x00, 0x00, 0x01, 0x02,
		avp.Mbit, 0xff, 0xff, 0xff,
	})
	writePipeBytes(t, remote, malformed)

	messageErr := receiveMessageError(t, handler.messageErrors)
	if messageErr.ResultCode != InvalidAVPLength || messageErr.Fatal {
		t.Fatalf("message error = %+v, want non-fatal %d", messageErr, InvalidAVPLength)
	}
	report := receiveRecordedError(t, handler.records, 1)
	var reported *MessageError
	if !errors.As(report, &reported) || reported != messageErr {
		t.Fatalf("reported error = %T(%v), want handled MessageError", report, report)
	}

	valid := NewRequest(DeviceWatchdog, 0, dict.Default)
	valid.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	valid.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	wire, err := valid.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	writePipeBytes(t, remote, wire)

	select {
	case got := <-handler.messages:
		if got.Header.CommandCode != DeviceWatchdog {
			t.Fatalf("dispatched command = %d, want %d", got.Header.CommandCode, DeviceWatchdog)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not continue to the valid message")
	}
}

func TestServerClosesAfterHandledFatalMessageError(t *testing.T) {
	handler := newRecordingMessageErrorHandler()
	remote, done := startPipeServer(t, handler, handler.records)
	defer closePipeServer(t, remote, done)

	writePipeBytes(t, remote, testMessageHeader(2, HeaderLength, RequestFlag))
	messageErr := receiveMessageError(t, handler.messageErrors)
	if messageErr.ResultCode != UnsupportedVersion || !messageErr.Fatal {
		t.Fatalf("message error = %+v, want fatal %d", messageErr, UnsupportedVersion)
	}
	if err := receiveRecordedError(t, handler.records, 1); !errors.Is(err, messageErr) {
		t.Fatalf("recorded error = %v, want %v", err, messageErr)
	}

	waitPipeServer(t, done)
	var b [1]byte
	if _, err := remote.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("read after fatal message error = %v, want EOF", err)
	}
}

func TestServerClosesWhenMessageErrorHandlerFails(t *testing.T) {
	handler := newRecordingMessageErrorHandler()
	handler.handleErr = errors.New("write failed")
	remote, done := startPipeServer(t, handler, handler.records)
	defer closePipeServer(t, remote, done)

	malformed := testFramedMessage(t, RequestFlag, []byte{
		0x00, 0x00, 0x01, 0x02,
		avp.Mbit, 0xff, 0xff, 0xff,
	})
	writePipeBytes(t, remote, malformed)
	_ = receiveMessageError(t, handler.messageErrors)

	report := receiveRecordedError(t, handler.records, 2)
	if !errors.Is(report, handler.handleErr) {
		t.Fatalf("reported error = %v, want joined handler failure", report)
	}
	waitPipeServer(t, done)
	var b [1]byte
	if _, err := remote.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("read after handler failure = %v, want EOF", err)
	}
}

func TestServerClosesWhenHandlerDoesNotSupportMessageErrors(t *testing.T) {
	handler := NewServeMux()
	logs := logtest.New()
	remote, done := startPipeServer(t, handler, logs)
	defer closePipeServer(t, remote, done)

	malformed := testFramedMessage(t, RequestFlag, []byte{
		0x00, 0x00, 0x01, 0x02,
		avp.Mbit, 0xff, 0xff, 0xff,
	})
	writePipeBytes(t, remote, malformed)

	report := receiveRecordedError(t, logs, 1)
	var messageErr *MessageError
	if !errors.As(report, &messageErr) {
		t.Fatalf("reported error = %T(%v), want MessageError", report, report)
	}
	waitPipeServer(t, done)
	var b [1]byte
	if _, err := remote.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("read after unsupported message error = %v, want EOF", err)
	}
}

func TestServeMuxRoutesMessageErrors(t *testing.T) {
	tests := []struct {
		name     string
		register func(*ServeMux, Handler)
	}{
		{
			name: "command",
			register: func(mux *ServeMux, handler Handler) {
				mux.Handle("CER", handler)
			},
		},
		{
			name: "command index",
			register: func(mux *ServeMux, handler Handler) {
				mux.HandleIdx(CommandIndex{AppID: 0, Code: CapabilitiesExchange, Request: true}, handler)
			},
		},
		{
			name: "catch-all after incapable command handler",
			register: func(mux *ServeMux, handler Handler) {
				mux.Handle("CER", HandlerFunc(func(Conn, *Message) {}))
				mux.Handle("ALL", handler)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := NewServeMux()
			handler := newRecordingMessageErrorHandler()
			tt.register(mux, handler)
			assertServerRoutesMessageError(t, mux, logtest.New(), handler)
		})
	}
}

func TestDefaultServeMuxRoutesMessageErrors(t *testing.T) {
	previous := DefaultServeMux
	DefaultServeMux = NewServeMux()
	t.Cleanup(func() { DefaultServeMux = previous })

	handler := newRecordingMessageErrorHandler()
	DefaultServeMux.Handle("CER", handler)
	assertServerRoutesMessageError(t, nil, logtest.New(), handler)
}

func assertServerRoutesMessageError(
	t *testing.T,
	serverHandler Handler,
	reports *logtest.Recorder,
	target *recordingMessageErrorHandler,
) {
	t.Helper()
	remote, done := startPipeServer(t, serverHandler, reports)
	defer closePipeServer(t, remote, done)

	malformed := testFramedMessage(t, RequestFlag, []byte{
		0x00, 0x00, 0x01, 0x02,
		avp.Mbit, 0xff, 0xff, 0xff,
	})
	writePipeBytes(t, remote, malformed)

	messageErr := receiveMessageError(t, target.messageErrors)
	if messageErr.ResultCode != InvalidAVPLength || messageErr.Fatal {
		t.Fatalf("message error = %+v, want non-fatal %d", messageErr, InvalidAVPLength)
	}
	report := receiveRecordedError(t, reports, 1)
	var reported *MessageError
	if !errors.As(report, &reported) || reported != messageErr {
		t.Fatalf("reported error = %T(%v), want routed MessageError", report, report)
	}
}

func startPipeServer(t *testing.T, handler Handler, records ...*logtest.Recorder) (net.Conn, <-chan struct{}) {
	t.Helper()
	local, remote := net.Pipe()
	srv := &Server{Handler: handler, Dict: dict.Default}
	if len(records) > 0 {
		srv.Logger = records[0].Logger()
	}
	c := srv.newConn(local)
	done := make(chan struct{})
	go func() {
		c.serve()
		close(done)
	}()
	return remote, done
}

func closePipeServer(t *testing.T, remote net.Conn, done <-chan struct{}) {
	t.Helper()
	if err := remote.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close pipe: %v", err)
	}
	waitPipeServer(t, done)
}

func waitPipeServer(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func writePipeBytes(t *testing.T, conn net.Conn, wire []byte) {
	t.Helper()
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
}

func receiveMessageError(t *testing.T, errors <-chan *MessageError) *MessageError {
	t.Helper()
	select {
	case err := <-errors:
		return err
	case <-time.After(time.Second):
		t.Fatal("message error handler was not called")
		return nil
	}
}

func receiveRecordedError(t *testing.T, records *logtest.Recorder, n int) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rs, err := records.Wait(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := logtest.Attr(rs[n-1], "error").Any().(error)
	if !ok {
		t.Fatal("record did not retain error value")
	}
	return got
}
