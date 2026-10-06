// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// rawAVP encodes an AVP header without Vendor-ID, the payload and padding.
func rawAVP(code uint32, payload []byte) []byte {
	b := make([]byte, 8, 8+len(payload)+3)
	binary.BigEndian.PutUint32(b[0:4], code)
	b[4] = avp.Mbit
	putUint24(b[5:8], uint32(8+len(payload)))
	b = append(b, payload...)
	return append(b, make([]byte, (4-len(b)%4)%4)...)
}

// TestDecodeFallbackDoesNotAliasInput checks that the datatype.Unknown kept
// on each decode-error fallback owns its bytes. ReadMessage decodes out of a
// pooled buffer that the next call reuses. Ownership is checked on a
// caller-owned buffer because sync.Pool reuse is not guaranteed.
func TestDecodeFallbackDoesNotAliasInput(t *testing.T) {
	badU32 := []byte{0x11, 0x11, 0x11, 0x11, 0x11} // 5 bytes for an Unsigned32
	// A Rating-Group header that declares 64 bytes inside a 12-byte payload.
	overlong := []byte{0, 0, 0x01, 0xb0, avp.Mbit, 0, 0, 64, 0x11, 0x11, 0x11, 0x11}
	for _, tc := range []struct {
		name   string
		data   []byte
		decode func(a *AVP, b []byte) error
	}{
		{
			name: "scalar size mismatch",
			data: rawAVP(avp.CCRequestNumber, badU32),
			decode: func(a *AVP, b []byte) error {
				return a.DecodeFromBytes(b, CHARGING_CONTROL_APP_ID, dict.Default)
			},
		},
		{
			name: "scalar invalid value",
			data: rawAVP(avp.HostIPAddress, []byte{255, 255, 0x11}),
			decode: func(a *AVP, b []byte) error {
				return a.DecodeFromBytes(b, 0, dict.Default)
			},
		},
		{
			name: "grouped invalid value",
			data: rawAVP(avp.VendorSpecificApplicationID, rawAVP(avp.HostIPAddress, []byte{255, 255, 0x11})),
			decode: func(a *AVP, b []byte) error {
				return a.DecodeFromBytes(b, 0, dict.Default)
			},
		},
		{
			name: "grouped member fails to decode",
			data: rawAVP(avp.MultipleServicesCreditControl, rawAVP(avp.RatingGroup, badU32)),
			decode: func(a *AVP, b []byte) error {
				return a.DecodeFromBytes(b, CHARGING_CONTROL_APP_ID, dict.Default)
			},
		},
		{
			name: "grouped member overruns its parent",
			data: rawAVP(avp.MultipleServicesCreditControl, overlong),
			decode: func(a *AVP, b []byte) error {
				return a.DecodeFromBytes(b, CHARGING_CONTROL_APP_ID, dict.Default)
			},
		},
		{
			name: "grouped nesting limit",
			data: nestedGroupedAVP(dict.DefaultMaxGroupedDepth + 1),
			decode: func(a *AVP, b []byte) error {
				return a.DecodeFromBytes(b, CHARGING_CONTROL_APP_ID, dict.Default)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := append([]byte(nil), tc.data...)
			a := &AVP{}
			if err := tc.decode(a, buf); err == nil {
				t.Fatal("expected an error from the fallback path")
			}
			u, ok := a.Data.(datatype.Unknown)
			if !ok {
				t.Fatalf("Data is %T, want datatype.Unknown", a.Data)
			}
			want := append([]byte(nil), u...)
			for i := range buf {
				buf[i] = 0xee
			}
			if !bytes.Equal(u, want) {
				t.Fatalf("Data changed when the input buffer was reused: got % x, want % x", []byte(u), want)
			}
		})
	}
}

// TestDecodedMembersDoNotAliasInput checks the Grouped members that leave the
// decoder: those DecodeGroupedFromBytes returns, and a Failed-AVP built from a
// member with a framing or payload error. Failed-AVP also retains undecodable
// members on a successful decode; those members must own their payloads.
func TestDecodedMembersDoNotAliasInput(t *testing.T) {
	badU32 := []byte{0x11, 0x11, 0x11, 0x11, 0x11} // 5 bytes for an Unsigned32
	owned := func(t *testing.T, buf []byte, data datatype.Type) {
		t.Helper()
		u, ok := data.(datatype.Unknown)
		if !ok {
			t.Fatalf("Data is %T, want datatype.Unknown", data)
		}
		want := append([]byte(nil), u...)
		for i := range buf {
			buf[i] = 0xee
		}
		if !bytes.Equal(u, want) {
			t.Fatalf("Data changed when the input buffer was reused: got % x, want % x", []byte(u), want)
		}
	}

	t.Run("DecodeGroupedFromBytes members", func(t *testing.T) {
		buf := append(rawAVP(avp.RatingGroup, []byte{0, 0, 0, 1}), rawAVP(avp.CCRequestNumber, badU32)...)
		g, err := DecodeGroupedFromBytes(buf, CHARGING_CONTROL_APP_ID, dict.Default)
		if err == nil || len(g.AVP) != 2 {
			t.Fatalf("got %d members, err = %v; want 2 members and an error", len(g.AVP), err)
		}
		owned(t, buf, g.AVP[1].Data)
	})

	for _, mode := range []string{"DecodeAVP", "DecodeFromBytes", "DecodeGroupedFromBytes", "ReadMessage"} {
		for _, nested := range []bool{false, true} {
			t.Run("decoded Failed-AVP members/"+mode+fmt.Sprint(nested), func(t *testing.T) {
				payload := append(rawAVP(avp.InbandSecurityID, []byte{0x11, 0x22}), rawAVP(avp.HostIPAddress, []byte{255, 255, 0x33})...)
				if nested {
					payload = rawAVP(avp.VendorSpecificApplicationID, payload)
				}
				buf := rawAVP(avp.FailedAVP, payload)
				want := append([]byte(nil), buf...)
				inputs := [][]byte{buf}
				var a *AVP
				var err error
				switch mode {
				case "DecodeAVP":
					a, err = DecodeAVP(buf, 0, dict.Default)
				case "DecodeFromBytes":
					a = &AVP{}
					err = a.DecodeFromBytes(buf, 0, dict.Default)
				case "DecodeGroupedFromBytes":
					var g *GroupedAVP
					g, err = DecodeGroupedFromBytes(buf, 0, dict.Default)
					if err == nil {
						a = g.AVP[0]
					}
				case "ReadMessage":
					reader := &decodeInputReader{Reader: bytes.NewReader(testFramedMessage(t, 0, buf))}
					var m *Message
					m, err = ReadMessage(reader, dict.Default)
					if err == nil {
						a = m.AVP[0]
					}
					inputs = reader.inputs
				}
				if err != nil {
					t.Fatalf("Failed-AVP decode: %v", err)
				}
				for _, input := range inputs {
					for i := range input {
						input[i] = 0xee
					}
				}
				got, err := a.Serialize()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("decoded Failed-AVP aliases input: got %x, want %x", got, want)
				}
			})
		}
	}

	t.Run("Failed-AVP of an overrunning member", func(t *testing.T) {
		// The member declares 13 bytes, so it fails to decode as an
		// Unsigned32 and its padding runs 3 bytes past the parent payload.
		member := rawAVP(avp.RatingGroup, badU32)[:13]
		parent := make([]byte, 8, 8+len(member))
		binary.BigEndian.PutUint32(parent[0:4], avp.MultipleServicesCreditControl)
		parent[4] = avp.Mbit
		putUint24(parent[5:8], uint32(8+len(member)))
		buf := append(append(parent, member...), 0, 0, 0)
		_, err := DecodeAVP(buf, CHARGING_CONTROL_APP_ID, dict.Default)
		var lengthErr *avpLengthError
		if !errors.As(err, &lengthErr) {
			t.Fatalf("err = %v, want an AVP length error", err)
		}
		failed, ok := lengthErr.failedAVP.Data.(*GroupedAVP)
		if !ok || len(failed.AVP) != 1 {
			t.Fatalf("Failed-AVP = %+v, want the parent holding the member", lengthErr.failedAVP)
		}
		owned(t, buf, failed.AVP[0].Data)
	})
	for _, tc := range []struct {
		name   string
		leaf   []byte
		depth  int
		result uint32
	}{
		{"length", rawAVP(avp.InbandSecurityID, []byte{0x11, 0x11}), 0, InvalidAVPLength},
		{"value", rawAVP(avp.HostIPAddress, []byte{255, 255, 0x11}), 0, InvalidAVPValue},
		{"nested length", rawAVP(avp.InbandSecurityID, []byte{0x11, 0x11}), 3, InvalidAVPLength},
		{"nested value", rawAVP(avp.HostIPAddress, []byte{255, 255, 0x11}), 3, InvalidAVPValue},
		{"nesting limit", rawAVP(avp.VendorSpecificApplicationID, rawAVP(avp.OriginHost, []byte("ignored"))), dict.DefaultMaxGroupedDepth, InvalidAVPValue},
	} {
		t.Run("Failed-AVP payload "+tc.name, func(t *testing.T) {
			buf := append([]byte(nil), tc.leaf...)
			for range tc.depth {
				buf = rawAVP(avp.VendorSpecificApplicationID, buf)
			}
			reader := &decodeInputReader{Reader: bytes.NewReader(testFramedMessage(t, RequestFlag, buf))}
			m, err := ReadMessage(reader, dict.Default)
			me := requirePayloadMessageError(t, m, err, tc.result)
			want, err := me.FailedAVP.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			// Overwrite the actual destination buffers supplied to the reader,
			// not its source bytes; these are the pooled decoder inputs.
			for _, input := range reader.inputs {
				for i := range input {
					input[i] = 0xee
				}
			}
			got, err := me.FailedAVP.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Failed-AVP changed after input reuse: got %x, want %x", got, want)
			}
		})
	}

}

// TestDecodeGroupedNestingLimitBoundsAllocation checks that an over-deep
// message is copied once, not once per enclosing Grouped AVP: copying at
// every level allocated 33 times the message size.
func TestDecodeGroupedNestingLimitBoundsAllocation(t *testing.T) {
	b := nestedMSCC(200000) // 1.6 MB
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := readMessageBytes(t, b, dict.Default)
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), errGroupedTooDeep.Error()) {
		t.Fatalf("err = %v, want the nesting limit error", err)
	}
	// Reading the body and keeping the outermost payload take one copy each.
	if got, limit := after.TotalAlloc-before.TotalAlloc, uint64(4*len(b)); got > limit {
		t.Fatalf("decoding a %d-byte message allocated %d bytes, want at most %d", len(b), got, limit)
	}
}

// nestedGroupedAVP returns depth Multiple-Services-Credit-Control AVPs,
// each containing the next. It is built in one pass: nesting by repeated
// rawAVP calls copies quadratically and would dominate timing tests.
func nestedGroupedAVP(depth int) []byte {
	b := make([]byte, 8*depth)
	for i := 0; i < depth; i++ {
		o := 8 * i
		binary.BigEndian.PutUint32(b[o:o+4], avp.MultipleServicesCreditControl)
		b[o+4] = avp.Mbit
		putUint24(b[o+5:o+8], uint32(len(b)-o))
	}
	return b
}

// nestedMSCC returns a Credit-Control request whose body is
// nestedGroupedAVP(depth) followed by a Session-Id AVP.
func nestedMSCC(depth int) []byte {
	body := append(nestedGroupedAVP(depth), rawAVP(avp.SessionID, []byte("session;1"))...)
	b := make([]byte, HeaderLength, HeaderLength+len(body))
	b[0] = 1
	putUint24(b[1:4], uint32(HeaderLength+len(body)))
	b[4] = RequestFlag
	putUint24(b[5:8], CreditControl)
	binary.BigEndian.PutUint32(b[8:12], CHARGING_CONTROL_APP_ID)
	return append(b, body...)
}

// groupedDepth returns how many Grouped AVPs are decoded along the first
// member chain of a.
func groupedDepth(a *AVP) int {
	depth := 0
	for {
		g, ok := a.Data.(*GroupedAVP)
		if !ok {
			return depth
		}
		depth++
		if len(g.AVP) == 0 {
			return depth
		}
		a = g.AVP[0]
	}
}

func readNested(t *testing.T, depth int, d *dict.Parser) (*Message, error) {
	t.Helper()
	return readMessageBytes(t, nestedMSCC(depth), d)
}

func readMessageBytes(t *testing.T, b []byte, d *dict.Parser) (*Message, error) {
	t.Helper()
	m, err := ReadMessage(bytes.NewReader(b), d)
	if m == nil {
		t.Fatalf("ReadMessage returned no message: %v", err)
	}
	return m, err
}

func lenientParser(t *testing.T, limit int) *dict.Parser {
	t.Helper()
	p, err := dict.NewParser("./dict/testdata/base.xml", "./dict/testdata/credit_control.xml")
	if err != nil {
		t.Fatal(err)
	}
	p.Strict = false
	p.MaxGroupedDepth = limit
	return p
}

func TestDecodeGroupedNestingLimit(t *testing.T) {
	limit := dict.DefaultMaxGroupedDepth
	if _, err := readNested(t, limit, dict.Default); err != nil {
		t.Fatalf("depth %d: unexpected error: %v", limit, err)
	}
	_, err := readNested(t, limit+1, dict.Default)
	if err == nil || !strings.Contains(err.Error(), errGroupedTooDeep.Error()) {
		t.Fatalf("depth %d: err = %v, want the nesting limit error", limit+1, err)
	}
}

// TestDecodeGroupedNestingLimitKeepsMessage checks that a Grouped AVP whose
// nesting exceeds the limit is kept as datatype.Unknown, like any Grouped AVP
// whose members fail to decode, and that the AVPs after it still decode at
// the right offset.
func TestDecodeGroupedNestingLimitKeepsMessage(t *testing.T) {
	const limit = 4
	m, err := readNested(t, limit+3, lenientParser(t, limit))
	if err != nil {
		t.Fatalf("lenient parser returned %v", err)
	}
	if m.DecodeErr == nil || !strings.Contains(m.DecodeErr.Error(), errGroupedTooDeep.Error()) {
		t.Fatalf("DecodeErr = %v, want the nesting limit error", m.DecodeErr)
	}
	if len(m.AVP) != 2 {
		t.Fatalf("decoded %d top-level AVPs, want 2", len(m.AVP))
	}
	u, ok := m.AVP[0].Data.(datatype.Unknown)
	if !ok {
		t.Fatalf("over-deep AVP holds %T, want datatype.Unknown", m.AVP[0].Data)
	}
	if want := nestedGroupedAVP(limit + 3)[8:]; !bytes.Equal(u, want) {
		t.Fatalf("over-deep AVP payload = % x, want % x", []byte(u), want)
	}
	sid, err := m.FindAVP(avp.SessionID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(sid.Data.(datatype.UTF8String)); got != "session;1" {
		t.Fatalf("Session-Id = %q after the over-deep AVP", got)
	}
}

// TestDecodeGroupedNestingLimitBoundsWork decodes nesting that took seconds
// before the limit existed: each level walked everything beneath it.
func TestDecodeGroupedNestingLimitBoundsWork(t *testing.T) {
	// Without the limit this took about 10 s; with it, milliseconds even
	// under the race detector, so the bound leaves room for a loaded runner.
	b := nestedMSCC(30000)
	start := time.Now()
	_, err := readMessageBytes(t, b, dict.Default)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), errGroupedTooDeep.Error()) {
		t.Fatalf("err = %v, want the nesting limit error", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("decoding 30000 nested Grouped AVPs took %v", elapsed)
	}
}

func TestDecodeGroupedNestingLimitFromParser(t *testing.T) {
	for _, tc := range []struct {
		name     string
		setting  int
		effetive int
	}{
		{"raised", 40, 40},
		{"lowered", 3, 3},
		{"zero means default", 0, dict.DefaultMaxGroupedDepth},
		{"negative means default", -1, dict.DefaultMaxGroupedDepth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := lenientParser(t, tc.setting)
			m, err := readNested(t, tc.effetive, p)
			if err != nil || m.DecodeErr != nil {
				t.Fatalf("depth %d: err = %v, DecodeErr = %v", tc.effetive, err, m.DecodeErr)
			}
			if got := groupedDepth(m.AVP[0]); got != tc.effetive {
				t.Fatalf("depth %d: decoded %d levels", tc.effetive, got)
			}
			m, _ = readNested(t, tc.effetive+1, p)
			if m.DecodeErr == nil || !strings.Contains(m.DecodeErr.Error(), errGroupedTooDeep.Error()) {
				t.Fatalf("depth %d: DecodeErr = %v, want the nesting limit error", tc.effetive+1, m.DecodeErr)
			}
		})
	}
}

// TestDecodeGroupedNestingLimitDirectEntryPoints covers the exported
// decoders that do not go through ReadMessage.
func TestDecodeGroupedNestingLimitDirectEntryPoints(t *testing.T) {
	limit := dict.DefaultMaxGroupedDepth
	nested := nestedGroupedAVP
	if _, err := DecodeAVP(nested(limit), CHARGING_CONTROL_APP_ID, dict.Default); err != nil {
		t.Fatalf("DecodeAVP at the limit: %v", err)
	}
	// Each enclosing Grouped AVP reports its member's error by text.
	_, err := DecodeAVP(nested(limit+1), CHARGING_CONTROL_APP_ID, dict.Default)
	if err == nil || !strings.Contains(err.Error(), errGroupedTooDeep.Error()) {
		t.Fatalf("DecodeAVP past the limit: err = %v", err)
	}
	// The payload of the outermost Grouped AVP is level 1.
	payload := nested(limit + 1)[8:]
	if _, err := DecodeGroupedFromBytes(payload, CHARGING_CONTROL_APP_ID, dict.Default); err == nil ||
		!strings.Contains(err.Error(), errGroupedTooDeep.Error()) {
		t.Fatalf("DecodeGroupedFromBytes past the limit: err = %v", err)
	}
	if _, err := DecodeGrouped(datatype.Grouped(nested(limit)[8:]), CHARGING_CONTROL_APP_ID, dict.Default); err != nil {
		t.Fatalf("DecodeGrouped at the limit: %v", err)
	}
}

// decodeInputReader retains the buffers passed to Read so ownership tests can
// simulate pool reuse after ReadMessage returns without relying on sync.Pool.
type decodeInputReader struct {
	io.Reader
	inputs [][]byte
}

func (r *decodeInputReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.inputs = append(r.inputs, b[:n])
	return n, err
}
