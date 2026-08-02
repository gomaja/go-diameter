// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"errors"
	"net"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

func benchmarkDiamTransport(b *testing.B, network string) {
	done := make(chan struct{}, 1)
	mux := NewServeMux()
	mux.HandleFunc("ALL", func(c Conn, m *Message) {
		done <- struct{}{}
	})

	ln, err := MultistreamListen(network, "127.0.0.1:0")
	if err != nil {
		b.Skipf("cannot listen on %s: %v", network, err)
	}

	srv := &Server{Handler: mux}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ln)
	}()
	defer func() {
		if err := srv.Close(); err != nil && !errors.Is(err, ErrServerClosed) {
			b.Fatalf("server close: %v", err)
		}
		if err := <-serveErr; err != nil && !errors.Is(err, ErrServerClosed) {
			b.Fatalf("serve: %v", err)
		}
	}()

	// Use the same dialer the library uses internally
	dialer := getMultistreamDialer(network, 0, nil)
	rwc, err := dialer.Dial(network, ln.Addr().String())
	if err != nil {
		b.Skipf("cannot dial %s: %v", network, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			b.Fatalf("close client: %v", err)
		}
	}()

	msg := NewRequest(257, 0, dict.Default)
	mustBenchmarkAVP(b, msg, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("bench.host"))
	mustBenchmarkAVP(b, msg, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("bench.realm"))
	mustBenchmarkAVP(b, msg, avp.HostIPAddress, avp.Mbit, 0, datatype.Address(net.ParseIP("127.0.0.1")))
	mustBenchmarkAVP(b, msg, avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(0))
	mustBenchmarkAVP(b, msg, avp.ProductName, 0, 0, datatype.UTF8String("bench"))
	payload, err := msg.Serialize()
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rwc.Write(payload); err != nil {
			b.Fatal(err)
		}
		<-done
	}
}

func mustBenchmarkAVP(b *testing.B, msg *Message, code interface{}, flags uint8, vendor uint32, data datatype.Type) {
	b.Helper()
	if _, err := msg.NewAVP(code, flags, vendor, data); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkDiamTransport_TCP(b *testing.B) {
	benchmarkDiamTransport(b, "tcp")
}

func BenchmarkDiamTransport_SCTP(b *testing.B) {
	benchmarkDiamTransport(b, "sctp")
}
