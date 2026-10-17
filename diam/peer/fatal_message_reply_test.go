package peer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-sctp"
)

type fatalMessageVector struct {
	name    string
	version uint8
	length  uint32
	code    uint32
}

var fatalMessageVectors = []fatalMessageVector{
	{"UnsupportedVersion", 2, diam.HeaderLength, diam.UnsupportedVersion},    // RFC 6733 §7.1.5.
	{"ShortLength", 1, diam.HeaderLength - 1, diam.InvalidMessageLength},     // RFC 6733 §§3, 7.1.5.
	{"UnalignedLength", 1, diam.HeaderLength + 1, diam.InvalidMessageLength}, // RFC 6733 §3, verified erratum 3805; §7.1.5.
}

func fatalMessageRequest(vector fatalMessageVector, iteration int) *diam.Message {
	return &diam.Message{Header: &diam.Header{
		Version: vector.version, MessageLength: vector.length,
		CommandFlags: diam.RequestFlag, CommandCode: diam.DeviceWatchdog,
		HopByHopID: uint32(iteration + 1), EndToEndID: uint32(iteration + 1001),
	}}
}

func fatalMessageRoundTrip(t *testing.T, h *parityTCP, vector fatalMessageVector, iteration int, admission ...bool) {
	t.Helper()
	request := fatalMessageRequest(vector, iteration)
	if len(admission) != 0 && admission[0] {
		request.Header.CommandCode = diam.CapabilitiesExchange
	}
	if err := h.wire.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	wire := request.Header.Serialize()
	if n, err := h.wire.Write(wire); err != nil || n != len(wire) {
		t.Fatalf("malformed request write=%d,%v; want %d", n, err, len(wire))
	}
	answer, err := diam.ReadMessage(h.wire, h.dict)
	if err != nil {
		t.Errorf("error answer: %v; want Result-Code %d before EOF", err, vector.code)
	} else if answer.Header.CommandFlags&diam.RequestFlag != 0 || answer.Header.CommandCode != request.Header.CommandCode ||
		answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID ||
		contractCode(t, answer) != vector.code {
		t.Errorf("error answer=%v; want correlated Result-Code %d", answer, vector.code)
	}
	h.event(t, *request.Header, h.frontend.replyDisposition(diam.ProtocolMalformedMessage, vector.code, true, true))
	h.eof(t)
	// Closing the manager joins its reporting workers, so a late failed-write
	// report cannot escape the assertion below.
	if h.manager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.manager.Close(ctx, sm.DisconnectRebooting); err != nil {
			t.Fatal(err)
		}
	}
	h.noEvents(t)
}

func TestProtocolTCPFatalMessageAnswerBeforeEOF(t *testing.T) {
	for _, frontend := range parityFrontends {
		t.Run(frontend.name, func(t *testing.T) {
			for _, vector := range fatalMessageVectors {
				t.Run(vector.name, func(t *testing.T) {
					for iteration := 0; iteration < 24; iteration++ {
						t.Run(fmt.Sprint(iteration), func(t *testing.T) {
							fatalMessageRoundTrip(t, parityStart(t, frontend, true), vector, iteration)
						})
					}
				})
			}
		})
	}
}

func TestManagerFatalMessageAnswerBeforeCER(t *testing.T) {
	frontend := parityFrontends[2]
	for _, vector := range fatalMessageVectors {
		t.Run(vector.name, func(t *testing.T) {
			for iteration := 0; iteration < 24; iteration++ {
				t.Run(fmt.Sprint(iteration), func(t *testing.T) {
					fatalMessageRoundTrip(t, parityStart(t, frontend, false), vector, iteration, true)
				})
			}
		})
	}
}

func TestManagerFatalRequestWhileWaitingForCEAClosesWithoutAnswer(t *testing.T) {
	frontend := parityFrontends[3]
	for _, vector := range fatalMessageVectors {
		t.Run(vector.name, func(t *testing.T) {
			h := parityStart(t, frontend, false)
			if cer := h.read(t); cer.Header.CommandCode != diam.CapabilitiesExchange || cer.Header.CommandFlags&diam.RequestFlag == 0 {
				t.Fatalf("initial message=%v; want CER", cer)
			}
			request := fatalMessageRequest(vector, 0)
			if _, err := h.wire.Write(request.Header.Serialize()); err != nil {
				t.Fatal(err)
			}
			h.event(t, *request.Header, frontend.replyDisposition(diam.ProtocolHandshakeState, vector.code, false, true))
			h.eof(t)
			h.noEvents(t)
		})
	}
}

func TestProtocolTCPTruncatedBodyClosesWithoutAnswer(t *testing.T) {
	for _, frontend := range parityFrontends {
		t.Run(frontend.name, func(t *testing.T) {
			h := parityStart(t, frontend, true)
			request := fatalMessageRequest(fatalMessageVector{version: 1, length: diam.HeaderLength + 8}, 0)
			if _, err := h.wire.Write(request.Header.Serialize()); err != nil {
				t.Fatal(err)
			}
			if err := h.wire.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			h.eof(t)
			h.noEvents(t)
		})
	}
}

func fatalMessageCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func fatalMessageManagerTransport(t *testing.T, frontend parityFrontend, network string) *parityTCP {
	t.Helper()
	h := &parityTCP{frontend: frontend, dict: contractDict(t), events: make(chan diam.ProtocolErrorEvent, 16), ready: make(chan struct{})}
	settings := contractSettings(h.dict, true, true)
	settings.OnProtocolError = func(e diam.ProtocolErrorEvent) { h.events <- e }
	manager, err := peer.New(peer.Config{Settings: settings, Timers: peer.Timers{CER: time.Hour, Closing: 5 * time.Second, TwInit: time.Hour},
		OnPeerEvent: func(e peer.PeerEvent) {
			if e.Peer.Eligible {
				select {
				case <-h.ready:
				default:
					close(h.ready)
				}
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	h.manager = manager
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manager.Close(ctx, sm.DisconnectRebooting); err != nil {
			t.Error(err)
		}
	})
	transport := network
	if network == "tls" {
		transport = "tcp"
	}
	listener, err := diam.MultistreamListen(transport, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var clientTLS *tls.Config
	if network == "tls" {
		cert := fatalMessageCertificate(t)
		roots := x509.NewCertPool()
		parsed, parseErr := x509.ParseCertificate(cert.Certificate[0])
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		roots.AddCert(parsed)
		clientTLS = &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13}
		listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	}
	pc := peer.PeerConfig{Host: "remote.example.net", NoAutoReconnect: true}
	if frontend.initiator {
		pc.Endpoints = []peer.Endpoint{{Network: transport, Address: listener.Addr().String(), TLSConfig: clientTLS}}
	}
	if err := manager.AddPeer(pc); err != nil {
		t.Fatal(err)
	}
	if !frontend.initiator {
		server := &diam.Server{Dict: h.dict}
		if err := manager.BindServer(server); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- server.Serve(listener) }()
		t.Cleanup(func() {
			_ = server.Close()
			if err := parityAwait(t, done); err != nil && !errors.Is(err, diam.ErrServerClosed) {
				t.Error(err)
			}
		})
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if frontend.initiator {
		h.wire, err = listener.Accept()
	} else if network == "tls" {
		h.wire, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", listener.Addr().String(), clientTLS)
	} else {
		var address *sctp.Addr
		address, err = sctp.ResolveAddr(transport, listener.Addr().String())
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			h.wire, err = sctp.Dial(ctx, transport, nil, address)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.wire.Close() })
	if frontend.initiator {
		cer := h.read(t)
		cea := contractBase(h.dict, diam.CapabilitiesExchange, false)
		cea.Header.HopByHopID, cea.Header.EndToEndID = cer.Header.HopByHopID, cer.Header.EndToEndID
		h.write(t, cea)
	} else {
		cer := contractBase(h.dict, diam.CapabilitiesExchange, true)
		h.write(t, cer)
		h.answer(t, cer, diam.Success)
	}
	parityAwait(t, h.ready)
	return h
}

func TestManagerTLSFatalMessageAnswerBeforeEOF(t *testing.T) { fatalMessageTransportCases(t, "tls") }
func TestManagerSCTPFatalMessageAnswerBeforeEOF(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SCTP sockets require Linux")
	}
	fatalMessageTransportCases(t, "sctp")
}

func fatalMessageTransportCases(t *testing.T, network string) {
	t.Helper()
	for _, frontend := range parityFrontends[2:] {
		t.Run(frontend.name, func(t *testing.T) {
			for _, vector := range fatalMessageVectors {
				t.Run(vector.name, func(t *testing.T) {
					for iteration := 0; iteration < 12; iteration++ {
						t.Run(fmt.Sprint(iteration), func(t *testing.T) {
							fatalMessageRoundTrip(t, fatalMessageManagerTransport(t, frontend, network), vector, iteration)
						})
					}
				})
			}
		})
	}
}

// A caller supplying a fatal body-error callback owns transport closure after
// the callback returns, as Server does for a fatal decoding error.
func TestProtocolTCPFatalBodyCallbackAnswerBeforeClosure(t *testing.T) {
	for _, frontend := range parityFrontends {
		t.Run(frontend.name, func(t *testing.T) {
			for iteration := 0; iteration < 24; iteration++ {
				t.Run(fmt.Sprint(iteration), func(t *testing.T) {
					h := parityStart(t, frontend, true)
					conn := h.connection(t)
					h.barrier(t)
					request := contractBase(h.dict, diam.DeviceWatchdog, true)
					request.Header.HopByHopID, request.Header.EndToEndID = uint32(iteration+1), uint32(iteration+1001)
					returned := make(chan error, 1)
					go func() {
						err := h.handler.HandleMessageError(conn, request, parityBodyError())
						conn.Close()
						returned <- err
					}()
					if err := h.wire.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatal(err)
					}
					answer, err := diam.ReadMessage(h.wire, h.dict)
					if err != nil {
						t.Errorf("error answer: %v; want Result-Code 5014 before EOF", err)
					} else if answer.Header.CommandFlags&diam.RequestFlag != 0 || answer.Header.CommandCode != request.Header.CommandCode ||
						answer.Header.HopByHopID != request.Header.HopByHopID || answer.Header.EndToEndID != request.Header.EndToEndID ||
						contractCode(t, answer) != diam.InvalidAVPLength {
						t.Errorf("error answer=%v; want correlated Result-Code 5014", answer)
					}
					h.callbackEvent(t, request, frontend.replyDisposition(diam.ProtocolMalformedMessage, diam.InvalidAVPLength, true, true))
					h.eof(t)
					if err := parityAwait(t, returned); err != nil {
						t.Fatal(err)
					}
					if h.manager != nil {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						if err := h.manager.Close(ctx, sm.DisconnectRebooting); err != nil {
							t.Fatal(err)
						}
					}
					h.noEvents(t)
				})
			}
		})
	}
}
