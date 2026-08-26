// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

var _ diam.MessageErrorHandler = (*StateMachine)(nil)

func TestStateMachineWritesMessageErrorAnswers(t *testing.T) {
	tests := []struct {
		name       string
		wire       []byte
		resultCode uint32
		failedAVP  bool
	}{
		{
			name: "unsupported version",
			wire: testSMErrorHeader(2, diam.HeaderLength,
				diam.RequestFlag|diam.ProxiableFlag|diam.RetransmittedFlag|0x08),
			resultCode: diam.UnsupportedVersion,
		},
		{
			name: "invalid message length",
			wire: testSMErrorHeader(1, 0,
				diam.RequestFlag|diam.ProxiableFlag|diam.RetransmittedFlag|0x08),
			resultCode: diam.InvalidMessageLength,
		},
		{
			name: "invalid AVP length",
			wire: testSMErrorMessage(t,
				diam.RequestFlag|diam.ProxiableFlag|diam.RetransmittedFlag|0x08,
				[]byte{
					0x00, 0x00, 0x01, 0x02,
					avp.Mbit, 0xff, 0xff, 0xff,
				}),
			resultCode: diam.InvalidAVPLength,
			failedAVP:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := testMessageErrorSettings()
			stateMachine := New(settings)
			server := diamtest.NewServer(stateMachine, dict.Default)
			defer server.Close()

			conn, err := net.DialTimeout("tcp", server.Addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			writeSMErrorWire(t, conn, tt.wire)

			answer, err := diam.ReadMessage(conn, dict.Default)
			if err != nil {
				t.Fatalf("read error answer: %v", err)
			}
			assertMessageErrorAnswer(t, answer, settings, tt.resultCode,
				diam.ErrorFlag|diam.ProxiableFlag, tt.failedAVP)
		})
	}
}

func TestStateMachineWritesMessageErrorAnswerThroughServeMux(t *testing.T) {
	settings := testMessageErrorSettings()
	stateMachine := New(settings)
	mux := diam.NewServeMux()
	mux.Handle("CER", stateMachine)
	server := diamtest.NewServer(mux, dict.Default)
	defer server.Close()

	conn, err := net.DialTimeout("tcp", server.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	malformed := testSMErrorMessage(t, diam.RequestFlag, []byte{
		0x00, 0x00, 0x01, 0x02,
		avp.Mbit, 0xff, 0xff, 0xff,
	})
	writeSMErrorWire(t, conn, malformed)

	answer, err := diam.ReadMessage(conn, dict.Default)
	if err != nil {
		t.Fatalf("read mux-routed error answer: %v", err)
	}
	assertMessageErrorAnswer(t, answer, settings, diam.InvalidAVPLength, diam.ErrorFlag, true)
}

func TestStateMachineContinuesAfterInvalidAVPLength(t *testing.T) {
	settings := testMessageErrorSettings()
	stateMachine := New(settings)
	server := diamtest.NewServer(stateMachine, dict.Default)
	defer server.Close()

	conn, err := net.DialTimeout("tcp", server.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	malformed := testSMErrorMessage(t, diam.RequestFlag, []byte{
		0x00, 0x00, 0x01, 0x02,
		avp.Mbit, 0xff, 0xff, 0xff,
	})
	writeSMErrorWire(t, conn, malformed)
	answer, err := diam.ReadMessage(conn, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	assertMessageErrorAnswer(t, answer, settings, diam.InvalidAVPLength, diam.ErrorFlag, true)

	writeValidSMErrorCER(t, conn)
	cea, err := diam.ReadMessage(conn, dict.Default)
	if err != nil {
		t.Fatalf("read CEA after handled message error: %v", err)
	}
	if !testResultCode(cea, diam.Success) {
		t.Fatalf("CEA after handled message error has wrong result:\n%s", cea)
	}
}

func TestStateMachineMessageErrorAnswerCopiesSessionID(t *testing.T) {
	settings := testMessageErrorSettings()
	stateMachine := New(settings)
	server := diamtest.NewServer(stateMachine, dict.Default)
	defer server.Close()

	conn, err := net.DialTimeout("tcp", server.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	body := []byte{
		0x00, 0x00, 0x01, 0x07,
		avp.Mbit, 0x00, 0x00, 0x0b,
		's', 'i', 'd', 0x00,
		0x00, 0x00, 0x01, 0x02,
		avp.Mbit, 0xff, 0xff, 0xff,
	}
	writeSMErrorWire(t, conn, testSMErrorMessage(t, diam.RequestFlag, body))
	answer, err := diam.ReadMessage(conn, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	wantCodes := []uint32{
		avp.SessionID,
		avp.OriginHost,
		avp.OriginRealm,
		avp.ResultCode,
		avp.OriginStateID,
		avp.FailedAVP,
	}
	if len(answer.AVP) != len(wantCodes) {
		t.Fatalf("answer AVP count = %d, want %d", len(answer.AVP), len(wantCodes))
	}
	for i, code := range wantCodes {
		if answer.AVP[i].Code != code {
			t.Fatalf("answer AVP[%d] = %d, want %d", i, answer.AVP[i].Code, code)
		}
	}
	if got := string(answer.AVP[0].Data.(datatype.UTF8String)); got != "sid" {
		t.Fatalf("Session-Id = %q, want sid", got)
	}
}

func TestStateMachineOmitsSessionIDThatWouldOverflowErrorAnswer(t *testing.T) {
	const maxAlignedMessageLength = diam.MaxMessageLength &^ 3
	settings := testMessageErrorSettings()
	stateMachine := New(settings)
	request := diam.NewRequest(diam.CapabilitiesExchange, 0, dict.Default)
	request.Header.HopByHopID = 0x01020304
	request.Header.EndToEndID = 0x05060708
	sessionDataLength := maxAlignedMessageLength - diam.HeaderLength - 8
	request.AddAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, oversizedSessionData(sessionDataLength)))
	failed := diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(0))
	conn := &messageErrorCaptureConn{}

	err := stateMachine.HandleMessageError(conn, request, &diam.MessageError{
		ResultCode: diam.InvalidAVPLength,
		FailedAVP:  failed,
	})
	if err != nil {
		t.Fatalf("HandleMessageError returned error: %v", err)
	}
	if conn.writeLen > maxAlignedMessageLength {
		t.Fatalf("error answer length = %d, exceeds %d", conn.writeLen, maxAlignedMessageLength)
	}
	answer, err := diam.ReadMessage(bytes.NewReader(conn.wire.Bytes()), dict.Default)
	if err != nil {
		t.Fatalf("decode bounded error answer: %v", err)
	}
	if _, err := answer.FindAVP(avp.SessionID, 0); err == nil {
		t.Fatal("oversized Session-Id was copied into the error answer")
	}
	assertMessageErrorAnswer(t, answer, settings, diam.InvalidAVPLength, diam.ErrorFlag, true)
}

func TestStateMachineDoesNotAnswerMalformedAnswer(t *testing.T) {
	settings := testMessageErrorSettings()
	stateMachine := New(settings)
	server := diamtest.NewServer(stateMachine, dict.Default)
	defer server.Close()

	conn, err := net.DialTimeout("tcp", server.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	malformedAnswer := testSMErrorMessage(t, 0, []byte{
		0x00, 0x00, 0x01, 0x02,
		avp.Mbit, 0xff, 0xff, 0xff,
	})
	writeSMErrorWire(t, conn, malformedAnswer)
	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("received bytes in response to a malformed answer")
	} else if errors.Is(err, io.EOF) {
		t.Fatal("server closed after a non-fatal malformed answer")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read after malformed answer = %v, want timeout with no bytes", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	writeValidSMErrorCER(t, conn)
	cea, err := diam.ReadMessage(conn, dict.Default)
	if err != nil {
		t.Fatalf("read CEA after malformed answer: %v", err)
	}
	if !testResultCode(cea, diam.Success) {
		t.Fatalf("CEA after malformed answer has wrong result:\n%s", cea)
	}
}

func assertMessageErrorAnswer(
	t *testing.T,
	answer *diam.Message,
	settings *Settings,
	resultCode uint32,
	wantFlags uint8,
	wantFailedAVP bool,
) {
	t.Helper()
	header := answer.Header
	if header.Version != 1 {
		t.Fatalf("answer version = %d, want 1", header.Version)
	}
	if header.CommandCode != diam.CapabilitiesExchange || header.ApplicationID != 0 {
		t.Fatalf("answer command/application = %d/%d", header.CommandCode, header.ApplicationID)
	}
	if header.HopByHopID != 0x01020304 || header.EndToEndID != 0x05060708 {
		t.Fatalf("answer identifiers = %#x/%#x", header.HopByHopID, header.EndToEndID)
	}
	if header.CommandFlags != wantFlags {
		t.Fatalf("answer flags = %#x, want %#x", header.CommandFlags, wantFlags)
	}
	if header.MessageLength%4 != 0 {
		t.Fatalf("answer length = %d, want four-octet alignment", header.MessageLength)
	}

	wantCodes := []uint32{avp.OriginHost, avp.OriginRealm, avp.ResultCode, avp.OriginStateID}
	if wantFailedAVP {
		wantCodes = append(wantCodes, avp.FailedAVP)
	}
	if len(answer.AVP) != len(wantCodes) {
		t.Fatalf("answer AVP count = %d, want %d: %v", len(answer.AVP), len(wantCodes), wantCodes)
	}
	for i, code := range wantCodes {
		if answer.AVP[i].Code != code {
			t.Fatalf("answer AVP[%d] = %d, want %d", i, answer.AVP[i].Code, code)
		}
	}
	if got := answer.AVP[0].Data.(datatype.DiameterIdentity); got != settings.OriginHost {
		t.Fatalf("Origin-Host = %q, want %q", got, settings.OriginHost)
	}
	if got := answer.AVP[1].Data.(datatype.DiameterIdentity); got != settings.OriginRealm {
		t.Fatalf("Origin-Realm = %q, want %q", got, settings.OriginRealm)
	}
	if got := uint32(answer.AVP[2].Data.(datatype.Unsigned32)); got != resultCode {
		t.Fatalf("Result-Code = %d, want %d", got, resultCode)
	}
	if got := answer.AVP[3].Data.(datatype.Unsigned32); got != settings.OriginStateID {
		t.Fatalf("Origin-State-Id = %d, want %d", got, settings.OriginStateID)
	}
	if !wantFailedAVP {
		return
	}
	failedGroup, ok := answer.AVP[4].Data.(*diam.GroupedAVP)
	if !ok {
		t.Fatalf("Failed-AVP data = %T, want *diam.GroupedAVP", answer.AVP[4].Data)
	}
	if len(failedGroup.AVP) != 1 {
		t.Fatalf("Failed-AVP children = %d, want 1", len(failedGroup.AVP))
	}
	failed := failedGroup.AVP[0]
	if failed.Code != avp.AuthApplicationID || failed.Len() != 12 {
		t.Fatalf("offending AVP = code %d length %d, want code %d length 12",
			failed.Code, failed.Len(), avp.AuthApplicationID)
	}
	if got := failed.Data.(datatype.Unsigned32); got != 0 {
		t.Fatalf("offending AVP zero payload decoded as %d", got)
	}
}

func testMessageErrorSettings() *Settings {
	return &Settings{
		OriginHost:    datatype.DiameterIdentity("server.example"),
		OriginRealm:   datatype.DiameterIdentity("example"),
		OriginStateID: datatype.Unsigned32(42),
	}
}

func testSMErrorHeader(version uint8, length uint32, flags uint8) []byte {
	return (&diam.Header{
		Version:       version,
		MessageLength: length,
		CommandFlags:  flags,
		CommandCode:   diam.CapabilitiesExchange,
		ApplicationID: 0,
		HopByHopID:    0x01020304,
		EndToEndID:    0x05060708,
	}).Serialize()
}

func testSMErrorMessage(t *testing.T, flags uint8, body []byte) []byte {
	t.Helper()
	length := diam.HeaderLength + len(body)
	if length%4 != 0 {
		t.Fatalf("test message length %d is not aligned", length)
	}
	wire := testSMErrorHeader(1, uint32(length), flags)
	return append(wire, body...)
}

func writeSMErrorWire(t *testing.T, conn net.Conn, wire []byte) {
	t.Helper()
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for len(wire) > 0 {
		n, err := conn.Write(wire)
		if err != nil {
			t.Fatal(err)
		}
		wire = wire[n:]
	}
}

func writeValidSMErrorCER(t *testing.T, conn net.Conn) {
	t.Helper()
	m := diam.NewRequest(diam.CapabilitiesExchange, 1001, dict.Default)
	mustSMClientAVP(t, m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example"))
	mustSMClientAVP(t, m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example"))
	mustSMClientAVP(t, m, avp.HostIPAddress, avp.Mbit, 0, datatype.Address(net.ParseIP("127.0.0.1")))
	mustSMClientAVP(t, m, avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(13))
	mustSMClientAVP(t, m, avp.ProductName, 0, 0, datatype.UTF8String("peer"))
	mustSMClientAVP(t, m, avp.OriginStateID, avp.Mbit, 0, datatype.Unsigned32(1))
	mustSMClientAVP(t, m, avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))
	var wire bytes.Buffer
	if _, err := m.WriteTo(&wire); err != nil {
		t.Fatal(err)
	}
	writeSMErrorWire(t, conn, wire.Bytes())
}

type oversizedSessionData int

func (d oversizedSessionData) Serialize() []byte { return nil }
func (d oversizedSessionData) Len() int          { return int(d) }
func (d oversizedSessionData) Padding() int      { return 0 }
func (d oversizedSessionData) Type() datatype.TypeID {
	return datatype.UTF8StringType
}
func (d oversizedSessionData) String() string { return "oversized Session-Id test data" }

type messageErrorCaptureConn struct {
	wire     bytes.Buffer
	writeLen int
	ctx      context.Context
}

func (c *messageErrorCaptureConn) Write(b []byte) (int, error) {
	c.writeLen = len(b)
	if len(b) > diam.MaxMessageLength {
		return 0, errors.New("test writer rejected an oversized Diameter message")
	}
	return c.wire.Write(b)
}

func (c *messageErrorCaptureConn) WriteStream(b []byte, _ uint) (int, error) {
	return c.Write(b)
}

func (c *messageErrorCaptureConn) Close()                         {}
func (c *messageErrorCaptureConn) LocalAddr() net.Addr            { return nil }
func (c *messageErrorCaptureConn) RemoteAddr() net.Addr           { return nil }
func (c *messageErrorCaptureConn) TLS() *tls.ConnectionState      { return nil }
func (c *messageErrorCaptureConn) Dictionary() *dict.Parser       { return dict.Default }
func (c *messageErrorCaptureConn) Context() context.Context       { return c.ctx }
func (c *messageErrorCaptureConn) SetContext(ctx context.Context) { c.ctx = ctx }
func (c *messageErrorCaptureConn) Connection() net.Conn           { return nil }
