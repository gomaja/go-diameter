package sm

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
)

func validatedCapture(t *testing.T, c *messageErrorCaptureConn) *diam.Message {
	t.Helper()
	m, err := diam.ReadMessage(bytes.NewReader(c.wire.Bytes()), dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	if validationErr := m.Validate(); validationErr != nil {
		t.Fatalf("library-built %d message: %v (Failed-AVP: %v)", m.Header.CommandCode, validationErr, validationErr.FailedAVP)
	}
	return m
}

func TestLibraryBuiltMessagesValidate(t *testing.T) {
	settings := testMessageErrorSettings()
	settings.HostIPAddresses = []datatype.Address{localhostAddress}
	settings.VendorID = datatype.Unsigned32(1)
	settings.ProductName = datatype.UTF8String("test")
	sm := New(settings)
	cli := &Client{Dict: dict.Default, Handler: sm}
	for _, build := range []struct {
		name string
		make func() (*diam.Message, error)
	}{
		{"CER", func() (*diam.Message, error) { return cli.makeCER(settings.HostIPAddresses) }},
		{"DWR", func() (*diam.Message, error) { return cli.makeDWR(1) }},
	} {
		t.Run(build.name, func(t *testing.T) {
			m, err := build.make()
			if err != nil {
				t.Fatal(err)
			}
			if validationErr := m.Validate(); validationErr != nil {
				t.Fatal(validationErr)
			}
		})
	}
	cer := diam.NewMessage(diam.CapabilitiesExchange, diam.RequestFlag|diam.ProxiableFlag|diam.RetransmittedFlag, 0, 1, 2, dict.Default)
	for _, tc := range []struct {
		name string
		send func(*messageErrorCaptureConn) error
	}{
		{"CEA-success", func(c *messageErrorCaptureConn) error { return successCEA(sm, c, cer) }},
		{"CEA-error", func(c *messageErrorCaptureConn) error { return errorCEA(sm, c, cer, smparser.ErrNoCommonApplication) }},
		{"error-answer", func(c *messageErrorCaptureConn) error {
			return sm.writeErrorAnswer(c, cer, diam.InvalidHDRBits, nil, true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &messageErrorCaptureConn{}
			if err := tc.send(c); err != nil {
				t.Fatal(err)
			}
			validatedCapture(t, c)
		})
	}
	t.Run("permanent-error-answer", func(t *testing.T) {
		request := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
		c := &messageErrorCaptureConn{}
		failed := diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("bad"))
		if err := sm.HandleMessageError(c, request, &diam.MessageError{ResultCode: diam.InvalidAVPLength, FailedAVP: failed}); err != nil {
			t.Fatal(err)
		}
		answer := validatedCapture(t, c)
		if answer.Header.CommandFlags&diam.ErrorFlag != 0 {
			t.Fatal("5xxx error answer has E bit")
		}
	})
	dpr := diam.NewRequest(diam.DisconnectPeer, 0, dict.Default)
	dpr.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, settings.OriginHost))
	dpr.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, settings.OriginRealm))
	dpr.AddAVP(diam.NewAVP(avp.DisconnectCause, avp.Mbit, 0, datatype.Enumerated(0)))
	if validationErr := dpr.Validate(); validationErr != nil {
		t.Fatalf("DPR: %v", validationErr)
	}
	dpr.Header.CommandFlags |= diam.ProxiableFlag | diam.RetransmittedFlag
	c := &messageErrorCaptureConn{}
	handleDPR(sm)(c, dpr)
	validatedCapture(t, c)
	dwr := diam.NewMessage(diam.DeviceWatchdog, diam.RequestFlag|diam.ProxiableFlag|diam.RetransmittedFlag, 0, 3, 4, dict.Default)
	dwr.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, settings.OriginHost))
	dwr.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, settings.OriginRealm))
	c = &messageErrorCaptureConn{}
	handleDWR(sm)(c, dwr)
	validatedCapture(t, c)
}
