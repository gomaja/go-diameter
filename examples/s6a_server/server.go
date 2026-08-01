// Copyright 2013-2015 go-diameter authors.  All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Diameter server example. This is by no means a complete server.
//
// If you'd like to test diameter over SSL, generate SSL certificates:
//   go run $GOROOT/src/crypto/tls/generate_cert.go --host localhost
//
// And start the server with `-cert_file cert.pem -key_file key.pem`.
//
// By default this server runs in a single OS thread. If you want to
// make it run on more, set the GOMAXPROCS=n environment variable.
// See Go's FAQ for details: http://golang.org/doc/faq#Why_no_multi_CPU

package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	_ "net/http/pprof"

	"io"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/sm"
)

const (
	VENDOR_3GPP = 10415
)

func main() {
	addr := flag.String("addr", ":3868", "address in the form of ip:port to listen on")
	ppaddr := flag.String("pprof_addr", ":9000", "address in form of ip:port for the pprof server")
	host := flag.String("diam_host", "server", "diameter identity host")
	realm := flag.String("diam_realm", "go-diameter", "diameter identity realm")
	certFile := flag.String("cert_file", "", "tls certificate file (optional)")
	keyFile := flag.String("key_file", "", "tls key file (optional)")
	networkType := flag.String("network_type", "tcp", "protocol type tcp/sctp")
	flag.Parse()

	settings := &sm.Settings{
		OriginHost:       datatype.DiameterIdentity(*host),
		OriginRealm:      datatype.DiameterIdentity(*realm),
		VendorID:         13,
		ProductName:      "go-diameter",
		FirmwareRevision: 1,
	}

	// Create the state machine (mux) and set .CollectGarbage(context.Background(), &protos.Void{})its message handlers.
	mux := sm.New(settings)

	mux.Handle("ULR", handleULR(*settings))
	mux.Handle("AIR", handleAIR(*settings))
	mux.HandleFunc("ALL", handleALL) // Catch all.

	// Print error reports.
	go printErrors(mux.ErrorReports())

	if len(*ppaddr) > 0 {
		go func() { log.Fatal(http.ListenAndServe(*ppaddr, nil)) }()
	}

	err := listen(*networkType, *addr, *certFile, *keyFile, mux)
	if err != nil {
		log.Fatal(err)
	}

}

func sendAIA(settings sm.Settings, w io.Writer, m *diam.Message) (n int64, err error) {

	if err := addAVP(m, avp.AuthenticationInfo, avp.Mbit, VENDOR_3GPP, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.EUTRANVector, avp.Mbit, VENDOR_3GPP, &diam.GroupedAVP{
				AVP: []*diam.AVP{
					diam.NewAVP(avp.RAND, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.OctetString("\x94\xbf/T\xc3v\xf3\x0e\x87\x83\x06k'\x18Z\x19")),
					diam.NewAVP(avp.XRES, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.OctetString("F\xf0\"\xb9%#\xf58")),
					diam.NewAVP(avp.AUTN, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.OctetString("\xc7G!;\xad~\x80\x00)\x08o%\x11\x0cP_")),
					diam.NewAVP(avp.KASME, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.OctetString("\xbf\x00\xf9\x80h3\"\x0e\xa1\x1c\xfa\x93\x03@\xd6\xf8\x02\xd51Y\xeb\xc4\x9d=\t\x14{\xeb!\xec\xcb:")),
				},
			}),
		},
	}); err != nil {
		return 0, err
	}

	return m.WriteTo(w)
}

func addAVP(m *diam.Message, code interface{}, flags uint8, vendor uint32, data datatype.Type) error {
	_, err := m.NewAVP(code, flags, vendor, data)
	return err
}

func handleAIR(settings sm.Settings) diam.HandlerFunc {
	type RequestedEUTRANAuthInfo struct {
		NumVectors        datatype.Unsigned32  `avp:"Number-Of-Requested-Vectors"`
		ImmediateResponse datatype.Unsigned32  `avp:"Immediate-Response-Preferred"`
		ResyncInfo        datatype.OctetString `avp:"Re-synchronization-Info"`
	}

	type AIR struct {
		SessionID               datatype.UTF8String       `avp:"Session-Id"`
		OriginHost              datatype.DiameterIdentity `avp:"Origin-Host"`
		OriginRealm             datatype.DiameterIdentity `avp:"Origin-Realm"`
		AuthSessionState        datatype.UTF8String       `avp:"Auth-Session-State"`
		UserName                string                    `avp:"User-Name"`
		VisitedPLMNID           datatype.OctetString      `avp:"Visited-PLMN-Id"`
		RequestedEUTRANAuthInfo RequestedEUTRANAuthInfo   `avp:"Requested-EUTRAN-Authentication-Info"`
	}
	return func(c diam.Conn, m *diam.Message) {
		var err error
		var req AIR
		var code uint32

		err = m.Unmarshal(&req)
		if err != nil {
			err = fmt.Errorf("unmarshal failed: %s", err)
			code = diam.UnableToComply
			log.Printf("Invalid AIR(%d): %s\n", code, err.Error())
		} else {
			code = diam.Success
		}

		a := m.Answer(code)
		// SessionID is required to be the AVP in position 1
		a.InsertAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, req.SessionID))
		if err := addAVP(a, avp.OriginHost, avp.Mbit, 0, settings.OriginHost); err != nil {
			log.Printf("Failed to create AIA Origin-Host: %s", err.Error())
			return
		}
		if err := addAVP(a, avp.OriginRealm, avp.Mbit, 0, settings.OriginRealm); err != nil {
			log.Printf("Failed to create AIA Origin-Realm: %s", err.Error())
			return
		}
		if err := addAVP(a, avp.OriginStateID, avp.Mbit, 0, settings.OriginStateID); err != nil {
			log.Printf("Failed to create AIA Origin-State-Id: %s", err.Error())
			return
		}
		_, err = sendAIA(settings, c, a)
		if err != nil {
			log.Printf("Failed to send AIA: %s", err.Error())
		}
	}
}

func sendULA(settings sm.Settings, w io.Writer, m *diam.Message) (n int64, err error) {

	if err := addAVP(m, avp.ULAFlags, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(1)); err != nil {
		return 0, err
	}
	if err := addAVP(m, avp.SubscriptionData, avp.Mbit, VENDOR_3GPP, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.MSISDN, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.OctetString("12345")),
			diam.NewAVP(avp.AccessRestrictionData, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(47)),
			diam.NewAVP(avp.SubscriberStatus, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(0)),
			diam.NewAVP(avp.NetworkAccessMode, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(2)),
			diam.NewAVP(avp.AMBR, avp.Mbit|avp.Vbit, VENDOR_3GPP, &diam.GroupedAVP{
				AVP: []*diam.AVP{
					diam.NewAVP(avp.MaxRequestedBandwidthDL, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(500)),
					diam.NewAVP(avp.MaxRequestedBandwidthUL, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(500)),
				},
			}),
			diam.NewAVP(avp.APNConfigurationProfile, avp.Mbit|avp.Vbit, VENDOR_3GPP, &diam.GroupedAVP{
				AVP: []*diam.AVP{
					diam.NewAVP(avp.ContextIdentifier, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(0)),
					diam.NewAVP(avp.AllAPNConfigurationsIncludedIndicator, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(0)),
					diam.NewAVP(avp.NetworkAccessMode, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(2)),
					diam.NewAVP(avp.APNConfiguration, avp.Mbit, VENDOR_3GPP, &diam.GroupedAVP{
						AVP: []*diam.AVP{
							diam.NewAVP(avp.ContextIdentifier, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(0)),
							diam.NewAVP(avp.PDNType, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(0)),
							diam.NewAVP(avp.ServiceSelection, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.UTF8String("oai.ipv4")),
							diam.NewAVP(avp.EPSSubscribedQoSProfile, avp.Mbit|avp.Vbit, VENDOR_3GPP, &diam.GroupedAVP{
								AVP: []*diam.AVP{
									diam.NewAVP(avp.QoSClassIdentifier, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(9)),
									diam.NewAVP(avp.AllocationRetentionPriority, avp.Mbit|avp.Vbit, VENDOR_3GPP, &diam.GroupedAVP{
										AVP: []*diam.AVP{
											diam.NewAVP(avp.PriorityLevel, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(15)),
											diam.NewAVP(avp.PreemptionCapability, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(1)),
											diam.NewAVP(avp.PreemptionVulnerability, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(0)),
										},
									}),
								},
							}),
						},
					}),
					diam.NewAVP(avp.AMBR, avp.Mbit|avp.Vbit, VENDOR_3GPP, &diam.GroupedAVP{
						AVP: []*diam.AVP{
							diam.NewAVP(avp.MaxRequestedBandwidthDL, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(500)),
							diam.NewAVP(avp.MaxRequestedBandwidthUL, avp.Mbit|avp.Vbit, VENDOR_3GPP, datatype.Unsigned32(500)),
						},
					}),
				},
			}),
		},
	}); err != nil {
		return 0, err
	}

	return m.WriteTo(w)
}

func handleULR(settings sm.Settings) diam.HandlerFunc {

	type ULR struct {
		SessionID        datatype.UTF8String       `avp:"Session-Id"`
		OriginHost       datatype.DiameterIdentity `avp:"Origin-Host"`
		OriginRealm      datatype.DiameterIdentity `avp:"Origin-Realm"`
		AuthSessionState datatype.Unsigned32       `avp:"Auth-Session-State"`
		UserName         datatype.UTF8String       `avp:"User-Name"`
		VisitedPLMNID    datatype.OctetString      `avp:"Visited-PLMN-Id"`
		RATType          datatype.Unsigned32       `avp:"RAT-Type"`
		ULRFlags         datatype.Unsigned32       `avp:"ULR-Flags"`
	}
	return func(c diam.Conn, m *diam.Message) {
		var err error
		var req ULR
		var code uint32

		err = m.Unmarshal(&req)
		if err != nil {
			err = fmt.Errorf("unmarshal failed: %s", err)
			code = diam.UnableToComply
			log.Printf("Invalid AIR(%d): %s\n", code, err.Error())
		} else {
			code = diam.Success
		}

		a := m.Answer(code)
		// SessionID is required to be the AVP in position 1
		a.InsertAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, req.SessionID))
		if err := addAVP(a, avp.AuthSessionState, avp.Mbit, 0, req.AuthSessionState); err != nil {
			log.Printf("Failed to create ULA Auth-Session-State: %s", err.Error())
			return
		}
		if err := addAVP(a, avp.OriginHost, avp.Mbit, 0, settings.OriginHost); err != nil {
			log.Printf("Failed to create ULA Origin-Host: %s", err.Error())
			return
		}
		if err := addAVP(a, avp.OriginRealm, avp.Mbit, 0, settings.OriginRealm); err != nil {
			log.Printf("Failed to create ULA Origin-Realm: %s", err.Error())
			return
		}
		if err := addAVP(a, avp.OriginStateID, avp.Mbit, 0, settings.OriginStateID); err != nil {
			log.Printf("Failed to create ULA Origin-State-Id: %s", err.Error())
			return
		}
		_, err = sendULA(settings, c, a)
		if err != nil {
			log.Printf("Failed to send ULA: %s", err.Error())
		}
	}
}

func printErrors(ec <-chan *diam.ErrorReport) {
	for err := range ec {
		log.Println(err)
	}
}

func listen(networkType, addr, cert, key string, handler diam.Handler) error {
	// Start listening for connections.
	if len(cert) > 0 && len(key) > 0 {
		log.Println("Starting secure diameter server on", addr)
		return diam.ListenAndServeNetworkTLS(networkType, addr, cert, key, handler, nil)
	}
	log.Println("Starting diameter server on", addr)
	return diam.ListenAndServeNetwork(networkType, addr, handler, nil)
}

func handleALL(c diam.Conn, m *diam.Message) {
	log.Printf("Received unexpected message from %s:\n%s", c.RemoteAddr(), m)
}
