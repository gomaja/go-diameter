//go:build linux && !386

// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
	"github.com/gomaja/go-sctp"
)

func TestHandleCER_VS_AuthSCTP(t *testing.T) {
	requireSCTP(t)
	testHandleCER_VS_Auth(t, "sctp")
}

func TestClientRefusesInbandTLSOnPlainSCTP(t *testing.T) {
	requireSCTP(t)
	testClientRefusesInbandTLSOnPlaintext(t, "sctp")
}

func TestAcceptedSCTPInvalidOpenCERAnswerBeforeEOF(t *testing.T) {
	requireSCTP(t)
	d := newSMTestDictionary(creditcontrol.Dictionary())
	cfg := *cloneTestSettings(serverSettings2, d)
	var hooks atomic.Int32
	cfg.OnCER = func(diam.Conn, *diam.Message) { hooks.Add(1) }
	admitted := make(chan diam.Conn, 1)
	cfg.OnHandshake = func(c diam.Conn, _ *smpeer.Metadata) { admitted <- c }
	server := diamtest.NewServerNetwork("sctp", mustNewStateMachine(t, &cfg, d), d)
	defer server.Close()
	address, err := sctp.ResolveAddr("sctp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wire, err := sctp.Dial(ctx, "sctp", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wire.Close() }()
	if err := wire.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	initial := acceptedRestartCER(t, "open.example", 1001, 111)
	if _, err := initial.WriteTo(wire); err != nil {
		t.Fatal(err)
	}
	cea, err := diam.ReadMessage(wire, d)
	if err != nil || !testResultCode(cea, diam.Success) {
		t.Fatalf("initial CEA=%v error=%v", cea, err)
	}
	protocolGenerationAwait(t, admitted)
	if hooks.Load() != 1 {
		t.Fatalf("initial OnCER count=%d", hooks.Load())
	}
	request := acceptedRestartCER(t, "open.example", 1001, 111)
	request.Header.CommandFlags |= diam.ProxiableFlag
	request.Header.HopByHopID, request.Header.EndToEndID = 0x55667788, 0x12345678
	if _, err := request.WriteTo(wire); err != nil {
		t.Fatal(err)
	}
	answer, err := diam.ReadMessage(wire, d)
	if err != nil {
		t.Fatalf("invalid Open CER answer: %v", err)
	}
	if answer.Header.CommandCode != diam.CapabilitiesExchange || answer.Header.CommandFlags != diam.ErrorFlag|diam.ProxiableFlag || answer.Header.ApplicationID != 0 || answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID || !testResultCode(answer, diam.InvalidHDRBits) {
		t.Fatalf("invalid Open CER answer=%v", answer)
	}
	for _, field := range []struct {
		code uint32
		want any
	}{{avp.OriginHost, cfg.OriginHost}, {avp.OriginRealm, cfg.OriginRealm}} {
		a, err := answer.FindAVP(field.code, 0)
		if err != nil || a.Data != field.want {
			t.Fatalf("answer AVP %d=%v error=%v; want %v", field.code, a, err, field.want)
		}
	}
	var b [1]byte
	if n, err := wire.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("association after 3008=%d,%v; want EOF", n, err)
	}
	if hooks.Load() != 1 {
		t.Fatalf("invalid Open CER invoked hook: count=%d", hooks.Load())
	}
}
