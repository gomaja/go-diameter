package sm

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
)

func TestCERNonStrictMalformedHostIPAddressAnswer(t *testing.T) {
	// RFC 6733 §§5.3, 7.1.5, 7.5 and Verified Erratum 4615.
	p := dict.New(dict.Base, dict.NASREQ, dict.CreditControl, dict.RoRf)
	p.SetStrict(false)
	server := diamtest.NewServer(mustNewStateMachine(t, testMessageErrorSettings()), p)
	defer server.Close()
	t.Logf("TCP server %s", server.Addr)
	request := regressionCER(t, p, 1001)
	bad := diam.NewAVP(avp.HostIPAddress, avp.Mbit, 0, datatype.Unknown([]byte{0, 1, 1, 2, 3}))
	request.AddAVP(bad)
	answer, conn := regressionExchange(t, server, request, p)
	if !testResultCode(answer, diam.InvalidAVPValue) {
		t.Fatalf("CEA = %v, want 5004", answer)
	}
	var failed []*diam.AVP
	for _, a := range answer.AVP {
		if a.Code == avp.FailedAVP && a.VendorID == 0 {
			failed = append(failed, a)
		}
	}
	if len(failed) != 1 {
		t.Fatalf("Failed-AVP count = %d, want one", len(failed))
	}
	group, ok := failed[0].Data.(*diam.GroupedAVP)
	if !ok || len(group.AVP) != 1 {
		t.Fatalf("Failed-AVP = %v, want one child", failed[0])
	}
	want, err := bad.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	got, err := group.AVP[0].Serialize()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Failed-AVP child = %x (%v), want %x", got, err, want)
	}
	if extra, err := diam.ReadMessage(conn, p); err == nil {
		t.Fatalf("connection stayed open after rejected CER: %v", extra)
	} else if !errors.Is(err, io.EOF) {
		t.Fatalf("read after CEA = %v, want EOF", err)
	}
}
