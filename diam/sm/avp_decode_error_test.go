// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package sm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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

func TestStateMachineAnswersUndecodableAVPs(t *testing.T) {
	for _, tc := range []struct {
		name            string
		code            uint32
		payload, failed []byte
		result          uint32
	}{
		{"length", avp.InbandSecurityID, []byte{1, 2}, []byte{1, 2}, diam.InvalidAVPLength},
		{"value", avp.HostIPAddress, []byte{255, 255, 1}, []byte{255, 255, 1}, diam.InvalidAVPValue},
	} {
		for _, stage := range []string{"CER", "after CER"} {
			t.Run(tc.name+"/"+stage, func(t *testing.T) {
				stateMachine := mustNewStateMachine(t, testMessageErrorSettings())
				server := diamtest.NewServer(stateMachine, dict.Default)
				defer server.Close()
				conn, err := net.DialTimeout("tcp", server.Addr, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = conn.Close() }()
				if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				t.Logf("TCP peer %s -> %s", conn.LocalAddr(), conn.RemoteAddr())
				if stage != "CER" {
					writeValidSMErrorCER(t, conn)
					cea, err := diam.ReadMessage(conn, dict.Default)
					if err != nil || !testResultCode(cea, diam.Success) {
						t.Fatalf("capability exchange: answer=%v error=%v", cea, err)
					}
				}
				command := uint32(diam.CapabilitiesExchange)
				flags := uint8(diam.RequestFlag)
				if stage != "CER" {
					command = diam.DeviceWatchdog
				}
				request := diam.NewMessage(command, flags, 0, 0x11223344, 0x55667788, dict.Default)
				request.AddAVP(diam.NewAVP(tc.code, avp.Mbit, 0, datatype.Unknown(tc.payload)))
				if _, err := request.WriteTo(conn); err != nil {
					t.Fatal(err)
				}
				answer, err := diam.ReadMessage(conn, dict.Default)
				if err != nil {
					t.Fatalf("read payload error answer: %v", err)
				}
				if answer.Header.CommandCode != command || answer.Header.CommandFlags != 0 || answer.Header.ApplicationID != 0 ||
					answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID {
					t.Fatalf("answer header = %+v, request = %+v", answer.Header, request.Header)
				}
				if !testResultCode(answer, tc.result) {
					t.Fatalf("want Result-Code %d: %v", tc.result, answer)
				}
				var failed []*diam.AVP
				for _, a := range answer.AVP {
					if a.Code == avp.FailedAVP {
						failed = append(failed, a)
					}
				}
				if len(failed) != 1 {
					t.Fatalf("Failed-AVP count = %d, want one (RFC 6733 §7.5, Erratum 4615)", len(failed))
				}
				want, err := diam.NewAVP(tc.code, avp.Mbit, 0, datatype.Unknown(tc.failed)).Serialize()
				if err != nil {
					t.Fatal(err)
				}
				if got := failed[0].Data.Serialize(); !bytes.Equal(got, want) {
					t.Fatalf("Failed-AVP bytes = %x, want %x", got, want)
				}
				select {
				case report := <-stateMachine.ErrorReports():
					var me *diam.MessageError
					if !errors.As(report.Error, &me) || me.ResultCode != tc.result || me.Fatal {
						t.Fatalf("report = %v", report.Error)
					}
				case <-time.After(time.Second):
					t.Fatal("missing decode error report")
				}
				if stage == "CER" {
					// RFC 6733 §§5.3 and 5.6.1: a rejected CER admits no peer and
					// the connection closes.
					if extra, err := diam.ReadMessage(conn, dict.Default); err == nil {
						t.Fatalf("connection stayed open after the rejected CER: %v", extra)
					} else if !errors.Is(err, io.EOF) {
						t.Fatalf("read after the rejected CER: %v, want EOF", err)
					}
					return
				}
				// A following DWR must get the next answer on this same connection.
				// Correlation IDs detect unexpected responses.
				dwr := diam.NewMessage(diam.DeviceWatchdog, diam.RequestFlag, 0, 0x12345678, 0x23456789, dict.Default)
				dwr.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
				dwr.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
				if _, err := dwr.WriteTo(conn); err != nil {
					t.Fatal(err)
				}
				dwa, err := diam.ReadMessage(conn, dict.Default)
				if err != nil {
					t.Fatalf("read following DWA: %v", err)
				}
				if dwa.Header.CommandCode != diam.DeviceWatchdog || dwa.Header.CommandFlags != 0 ||
					dwa.Header.HopByHopID != dwr.Header.HopByHopID || dwa.Header.EndToEndID != dwr.Header.EndToEndID || !testResultCode(dwa, diam.Success) {
					t.Fatalf("following answer = %v, want successful DWA with matching IDs", dwa)
				}
			})
		}
	}
}

func TestStateMachineErrorAnswerDoesNotEchoMalformedRequiredAVP(t *testing.T) {
	for _, badCode := range []uint32{avp.CCRequestType, avp.CCRequestNumber} {
		t.Run(fmt.Sprint(badCode), func(t *testing.T) {
			server := diamtest.NewServer(mustNewStateMachine(t, testMessageErrorSettings()), dict.Default)
			defer server.Close()
			conn, err := net.DialTimeout("tcp", server.Addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			t.Logf("TCP peer %s -> %s", conn.LocalAddr(), conn.RemoteAddr())
			writeValidSMErrorCER(t, conn)
			cea, err := diam.ReadMessage(conn, dict.Default)
			if err != nil || !testResultCode(cea, diam.Success) {
				t.Fatalf("CEA: %v, %v", cea, err)
			}
			ccr := diam.NewRequest(diam.CreditControl, diam.CHARGING_CONTROL_APP_ID, dict.Default)
			ccr.Header.CommandFlags |= diam.ProxiableFlag
			for _, a := range []*diam.AVP{
				diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("session;1")),
				diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")),
				diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")),
				diam.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")),
				diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4)),
				diam.NewAVP(avp.ServiceContextID, avp.Mbit, 0, datatype.UTF8String("test")),
				diam.NewAVP(avp.CCRequestType, avp.Mbit, 0, datatype.Enumerated(3)),
				diam.NewAVP(avp.CCRequestNumber, avp.Mbit, 0, datatype.Unsigned32(123)),
			} {
				if a.Code == badCode {
					a = diam.NewAVP(badCode, avp.Mbit, 0, datatype.Unknown([]byte{0, 1}))
				}
				ccr.AddAVP(a)
			}
			if _, err := ccr.WriteTo(conn); err != nil {
				t.Fatal(err)
			}
			cca, readErr := diam.ReadMessage(conn, dict.Default)
			if cca == nil {
				t.Fatal(readErr)
			}
			for _, want := range []struct {
				code  uint32
				value uint32
			}{{avp.CCRequestType, 3}, {avp.CCRequestNumber, 123}, {avp.AuthApplicationID, 4}} {
				var a *diam.AVP
				for _, member := range cca.AVP {
					if member.Code == want.code && member.VendorID == 0 {
						a = member
						break
					}
				}
				if a == nil {
					t.Fatalf("CCA missing top-level AVP %d", want.code)
				}
				if want.code == badCode {
					want.value = 0
				}
				if _, raw := a.Data.(datatype.Unknown); raw || a.Data.Len() != 4 {
					t.Fatalf("CCA top-level AVP %d echoes malformed payload: %v", want.code, a)
				}
				if got := binary.BigEndian.Uint32(a.Data.Serialize()); got != want.value {
					t.Fatalf("CCA AVP %d = %d, want %d", want.code, got, want.value)
				}
			}
			if readErr != nil || cca.DecodeErr != nil {
				t.Fatalf("strict CCA decode: %v, DecodeErr=%v", readErr, cca.DecodeErr)
			}
			if !testResultCode(cca, diam.InvalidAVPLength) {
				t.Fatalf("CCA = %v", cca)
			}
			assertPayloadFailedAVP(t, cca, badCode, []byte{0, 1})
		})
	}
}

func TestStrictClientReceivesPayloadErrorAnswer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    uint32
		payload []byte
		result  uint32
	}{
		{"5014", avp.InbandSecurityID, []byte{1, 2}, diam.InvalidAVPLength},
		{"5004", avp.HostIPAddress, []byte{255, 255, 1}, diam.InvalidAVPValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := diamtest.NewServer(mustNewStateMachine(t, testMessageErrorSettings()), dict.Default)
			defer server.Close()
			cfg := &Settings{OriginHost: "peer.example", OriginRealm: "example", VendorID: 13, ProductName: "test"}
			clientSM := mustNewStateMachine(t, cfg)
			got := make(chan *diam.Message, 1)
			clientSM.HandleFunc("DWA", func(_ diam.Conn, m *diam.Message) { got <- m })
			client := &Client{Handler: clientSM, Dict: dict.Default, AcctApplicationID: []*diam.AVP{diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(1001))}}
			conn, err := client.Dial(server.Addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			t.Logf("TCP peer %s -> %s", conn.LocalAddr(), conn.RemoteAddr())
			dwr := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
			dwr.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, cfg.OriginHost))
			dwr.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, cfg.OriginRealm))
			dwr.AddAVP(diam.NewAVP(tc.code, avp.Mbit, 0, datatype.Unknown(tc.payload)))
			if _, err := dwr.WriteTo(conn); err != nil {
				t.Fatal(err)
			}
			select {
			case answer := <-got:
				if answer.DecodeErr != nil || !testResultCode(answer, tc.result) {
					t.Fatalf("DWA = %v", answer)
				}
				if answer.Header.CommandFlags != 0 || answer.Header.HopByHopID != dwr.Header.HopByHopID || answer.Header.EndToEndID != dwr.Header.EndToEndID {
					t.Fatalf("DWA header = %+v", answer.Header)
				}
				assertPayloadFailedAVP(t, answer, tc.code, tc.payload)
			case <-time.After(time.Second):
				t.Fatal("strict client's DWA handler did not receive the payload error answer")
			}
		})
	}
}

func assertPayloadFailedAVP(t *testing.T, m *diam.Message, code uint32, payload []byte) {
	t.Helper()
	var containers []*diam.AVP
	for _, a := range m.AVP {
		if a.Code == avp.FailedAVP && a.VendorID == 0 {
			containers = append(containers, a)
		}
	}
	if len(containers) != 1 {
		t.Fatalf("Failed-AVP count = %d, want 1", len(containers))
	}
	g, ok := containers[0].Data.(*diam.GroupedAVP)
	if !ok || len(g.AVP) != 1 {
		t.Fatalf("Failed-AVP = %v", containers[0])
	}
	leaf := g.AVP[0]
	if leaf.Code != code || leaf.Flags != avp.Mbit || leaf.VendorID != 0 || leaf.Length != 8+len(payload) || !bytes.Equal(leaf.Data.Serialize(), payload) {
		t.Fatalf("Failed-AVP leaf = %v, want code %d payload %x", leaf, code, payload)
	}
}
