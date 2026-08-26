//go:build linux && !386

// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

func requireSCTP(t *testing.T) {
	t.Helper()
	ln, err := diam.MultistreamListen("sctp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close SCTP listener: %v", err)
	}
}

func TestHandleCER_HandshakeMetadataSCTP(t *testing.T) {
	requireSCTP(t)
	testHandleCER_HandshakeMetadata(t, "sctp")
}

func TestClient_Handshake_CustomIP_SCTP(t *testing.T) {
	requireSCTP(t)
	testClient_Handshake_CustomIP(t, "sctp")
}

// TestStateMachineSCTP establishes a connection with a test SCTP server and
// sends a Re-Auth-Request message to ensure the handshake was
// completed and that the RAR handler has context from the peer.
func TestStateMachineSCTP(t *testing.T) {
	requireSCTP(t)
	testStateMachine(t, "sctp")
}

func TestStateMachineMessageErrorSCTPStream(t *testing.T) {
	requireSCTP(t)
	settings := testMessageErrorSettings()
	server := diamtest.NewServerNetwork("sctp", New(settings), dict.Default)
	defer server.Close()

	answers := make(chan *diam.Message, 1)
	handler := diam.NewServeMux()
	handler.Handle("CEA", diam.HandlerFunc(func(_ diam.Conn, message *diam.Message) {
		answers <- message
	}))
	client, err := diam.DialNetwork("sctp", server.Addr, handler, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Connection().Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close SCTP client: %v", err)
		}
	}()

	const stream = 7
	wire := testSMErrorHeader(2, diam.HeaderLength, diam.RequestFlag|diam.ProxiableFlag)
	if _, err := client.WriteStream(wire, stream); err != nil {
		t.Fatal(err)
	}

	select {
	case answer := <-answers:
		if got := answer.MessageStream(); got != stream {
			t.Fatalf("error answer stream = %d, want %d", got, stream)
		}
		assertMessageErrorAnswer(t, answer, settings, diam.UnsupportedVersion,
			diam.ErrorFlag|diam.ProxiableFlag, false)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SCTP message error answer")
	}
}
