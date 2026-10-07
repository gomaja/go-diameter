package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/validation"
)

// RFC 6733 §6.2: a local handler must copy a present Session-Id.
func TestOutgoingAnswerRequiresSessionID(t *testing.T) {
	r := NewRequest(SessionTermination, 0, dict.Default)
	r.AddAVP(NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("present")))
	a := r.Answer(UnableToComply)
	a.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("host.example")))
	a.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := a.ValidateOutgoing(); err == nil || err.ResultCode != MissingAVP {
		t.Fatalf("handler omitted Session-Id: %v", err)
	}
	a.InsertAVP(r.AVP[0])
	if err := a.ValidateOutgoing(); err != nil {
		t.Fatal(err)
	}
}

// RFC 6733 §6.2: echo once, without sharing mutable data with the request.
func TestAnswerCopiesProxyInfo(t *testing.T) {
	state := NewAVP(avp.ProxyState, avp.Mbit, 0, datatype.OctetString("original"))
	nested := NewAVP(999999, 0, 0, &GroupedAVP{AVP: []*AVP{NewAVP(999998, 0, 0, datatype.Unknown{1, 2, 3})}})
	p := NewAVP(avp.ProxyInfo, avp.Mbit, 0, &GroupedAVP{AVP: []*AVP{NewAVP(avp.ProxyHost, avp.Mbit, 0, datatype.DiameterIdentity("proxy.example")), state, nested}})
	r := NewRequest(SessionTermination, 0, dict.Default)
	r.AddAVP(p)
	before := append([]byte(nil), p.Data.Serialize()...)
	a := r.Answer(Success)
	proxies := a.FindAVPsWithPath(AVPRef{Code: avp.ProxyInfo})
	if len(proxies) != 1 {
		t.Fatalf("echo count %d", len(proxies))
	}
	group := proxies[0].Data.(*GroupedAVP)
	group.AVP[1].Data = datatype.OctetString("changed")
	group.AVP[2].Data.(*GroupedAVP).AVP[0].Data.(datatype.Unknown)[0] = 9
	group.AVP[0].Flags = 0
	if !bytes.Equal(p.Data.Serialize(), before) {
		t.Fatal("answer mutation changed request")
	}
}

// Peer echoes bypass sending checks; newly constructed malformed groups do not.
func TestProxyInfoEchoValidation(t *testing.T) {
	r := NewRequest(DeviceWatchdog, 0, dict.Default)
	r.AddAVP(NewAVP(avp.ProxyInfo, 1, 0, &GroupedAVP{}))
	a := r.Answer(UnableToComply)
	a.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("host.example")))
	a.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	if err := a.ValidateOutgoing(); err != nil {
		t.Fatalf("echo rejected: %v", err)
	}
	a.AddAVP(NewAVP(avp.ProxyInfo, avp.Mbit, 0, &GroupedAVP{}))
	if err := a.ValidateOutgoing(); err == nil {
		t.Fatal("new malformed proxy accepted")
	}
}

// RFC 6733 §6.2's exception applies only to error answers, never requests (N13).
func TestErrorBuilderSessionOptionScope(t *testing.T) {
	_, commands := baseWireSpec(t)
	for _, c := range commands {
		if !c.Request || c.Rules[0].Name != "Session-Id" {
			continue
		}
		m := baseCommandMessage(t, 0, c)
		m.AVP = m.AVP[1:]
		m.AddAVP(NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(UnableToComply)))
		if err := m.ValidateErrorAnswer(validation.WithoutSessionID()); err == nil || err.ResultCode != MissingAVP {
			t.Fatalf("request relaxed: %v", err)
		}
	}
	for _, result := range []uint32{1001, 2001, 3001, 4001, 5001, 5999, 6000} {
		m := baseMissingAnswer()
		m.AVP = m.AVP[:3]
		m.AVP[0].Data = datatype.Unsigned32(result)
		err := m.ValidateErrorAnswer(validation.WithoutSessionID())
		if (err == nil) != (result >= 3000 && result < 6000) {
			t.Fatalf("result %d: %v", result, err)
		}
		if err := m.ValidateErrorAnswer(validation.ErrorAnswer{}); err == nil {
			t.Fatal("zero option relaxed presence")
		}
		if err := m.ValidateOutgoing(); err == nil {
			t.Fatal("option leaked to public validation")
		}
		m.AVP[1].Flags = 0
		if err := m.ValidateErrorAnswer(validation.WithoutSessionID()); err == nil || err.ResultCode != InvalidAVPBits {
			t.Fatalf("other sending rules relaxed: %v", err)
		}
		m.AVP[1].Flags = avp.Mbit
		m.AVP = m.AVP[:2]
		if err := m.ValidateErrorAnswer(validation.WithoutSessionID()); err == nil {
			t.Fatal("relaxed Origin-Realm presence")
		}
	}
}

func TestProxyInfoEchoScope(t *testing.T) {
	r := NewRequest(DeviceWatchdog, 0, dict.Default)
	r.AddAVP(NewAVP(avp.ProxyInfo, avp.Mbit, 0, &GroupedAVP{}))
	a := r.Answer(Success)
	a.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("host.example")))
	a.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	if err := a.ValidateOutgoing(); err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err == nil {
		t.Fatal("receive grammar bypassed by echo provenance")
	}
	a.Header.CommandFlags |= RequestFlag
	if err := a.ValidateOutgoing(); err == nil {
		t.Fatal("request inherited echo exemption")
	}
	a.Header.CommandFlags &^= RequestFlag
	proxy := a.FindAVPsWithPath(AVPRef{Code: avp.ProxyInfo})[0]
	proxy.VendorID = 10415
	proxy.Flags = avp.Vbit | avp.Mbit | 1
	if err := a.ValidateOutgoing(); err == nil {
		t.Fatal("vendor AVP inherited echo exemption")
	}
	proxy.VendorID = 0
	proxy.Flags = avp.Mbit
	proxy.Code = avp.VendorSpecificApplicationID
	if err := a.ValidateOutgoing(); err == nil {
		t.Fatal("changed identity inherited echo exemption")
	}
}

func FuzzProxyInfoEcho(f *testing.F) {
	f.Add([]byte{1, 2, 3}, uint8(0x41))
	f.Add([]byte{}, uint8(0))
	f.Fuzz(func(t *testing.T, payload []byte, flags uint8) {
		if len(payload) > 4096 {
			t.Skip()
		}
		flags &^= avp.Vbit
		r := NewRequest(DeviceWatchdog, 0, dict.Default)
		p := NewAVP(avp.ProxyInfo, flags, 0, &GroupedAVP{AVP: []*AVP{NewAVP(999999, flags, 0, datatype.Unknown(payload))}})
		r.AddAVP(p)
		wire, err := r.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := ReadMessage(bytes.NewReader(wire), dict.Default)
		if err != nil {
			t.Fatal(err)
		}
		a := decoded.Answer(Success)
		a.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("host.example")))
		a.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
		if err := a.ValidateOutgoing(); err != nil {
			t.Fatal(err)
		}
		echo := a.FindAVPsWithPath(AVPRef{Code: avp.ProxyInfo})
		expected := NewAVP(999999, flags&^0x1f, 0, datatype.Unknown(payload))
		if len(echo) != 1 || echo[0].Flags != p.Flags&^0x1f || !bytes.Equal(echo[0].Data.Serialize(), (&GroupedAVP{AVP: []*AVP{expected}}).Serialize()) {
			t.Fatal("echo changed")
		}
		copied := echo[0].Data.(*GroupedAVP).AVP[0].Data.(datatype.Unknown)
		if len(copied) > 0 {
			copied[0] ^= 0xff
			if bytes.Equal(copied, decoded.AVP[0].Data.(*GroupedAVP).AVP[0].Data.Serialize()) {
				t.Fatal("shared echo payload")
			}
		}
	})
}

// RFC 6733 §§4.1, 6.2: clear reserved flags at every depth without changing
// vendor identity, M/P bits, payloads, or the request's storage.
func TestProxyInfoEchoClearsReservedFlags(t *testing.T) {
	leaf := NewAVP(999999, 0xff, 10415, datatype.Unknown{0, 1, 255})
	nested := NewAVP(avp.ProxyInfo, 0x7f, 0, &GroupedAVP{AVP: []*AVP{leaf}})
	parent := NewAVP(avp.ProxyInfo, 0x3f, 0, &GroupedAVP{AVP: []*AVP{nested}})
	r := NewRequest(DeviceWatchdog, 0, dict.Default)
	r.AddAVP(parent)
	before := append([]byte(nil), parent.Data.Serialize()...)
	a := r.Answer(Success)
	p := a.FindAVPsWithPath(AVPRef{Code: avp.ProxyInfo})[0]
	n := p.Data.(*GroupedAVP).AVP[0]
	l := n.Data.(*GroupedAVP).AVP[0]
	if p.Flags != 0x20 || n.Flags != 0x60 || l.Flags != 0xe0 || l.VendorID != 10415 || !bytes.Equal(l.Data.Serialize(), leaf.Data.Serialize()) {
		t.Fatal("reserved flags or peer contents incorrect")
	}
	if parent.Flags != 0x3f || !bytes.Equal(before, parent.Data.Serialize()) {
		t.Fatal("request changed")
	}
}

// TestProxyInfoEchoExemptionEndsOnChange checks that the outgoing exemption
// covers an echoed Proxy-Info only as Answer copied it: a caller that alters
// it afterwards is sending its own AVP, which the sending rules check.
func TestProxyInfoEchoExemptionEndsOnChange(t *testing.T) {
	r := NewRequest(DeviceWatchdog, 0, dict.Default)
	// The peer cleared M on Proxy-Info, which our sending rules require.
	r.AddAVP(NewAVP(avp.ProxyInfo, 0, 0, &GroupedAVP{AVP: []*AVP{
		NewAVP(avp.ProxyHost, avp.Mbit, 0, datatype.DiameterIdentity("proxy.example")),
		NewAVP(avp.ProxyState, avp.Mbit, 0, datatype.OctetString("state")),
	}}))
	a := r.Answer(Success)
	a.AddAVP(NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("host.example")))
	a.AddAVP(NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	if err := a.ValidateOutgoing(); err != nil {
		t.Fatalf("unchanged echo rejected: %v", err)
	}
	proxy := a.FindAVPsWithPath(AVPRef{Code: avp.ProxyInfo})[0]
	group := proxy.Data.(*GroupedAVP)
	group.AVP = group.AVP[:1]
	if err := a.ValidateOutgoing(); err == nil {
		t.Fatal("echo changed after Answer kept its exemption")
	}
}
