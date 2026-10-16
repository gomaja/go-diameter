package sm

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/diamtest"
)

type finalDPARead struct {
	data []byte
	err  error
}
type finalDPATransport struct {
	reads              chan finalDPARead
	writes             chan *diam.Message
	closed, eofRead    chan struct{}
	closeOnce, eofOnce sync.Once
	pending            finalDPARead
	dprWriteRelease    <-chan struct{}
}

func (c *finalDPATransport) Read(b []byte) (int, error) {
	if len(c.pending.data) == 0 && c.pending.err == nil {
		select {
		case c.pending = <-c.reads:
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	n := copy(b, c.pending.data)
	c.pending.data = c.pending.data[n:]
	if len(c.pending.data) > 0 {
		return n, nil
	}
	err := c.pending.err
	c.pending = finalDPARead{}
	if err == io.EOF {
		c.eofOnce.Do(func() { close(c.eofRead) })
	}
	return n, err
}
func (c *finalDPATransport) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	m, err := diam.ReadMessage(bytes.NewReader(b), nil)
	if err != nil {
		return 0, err
	}
	c.writes <- m
	if m.Header.CommandCode == diam.DisconnectPeer && c.dprWriteRelease != nil {
		<-c.dprWriteRelease
	}
	return len(b), nil
}
func (c *finalDPATransport) Close() error { c.closeOnce.Do(func() { close(c.closed) }); return nil }
func (*finalDPATransport) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10001}
}
func (*finalDPATransport) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 3868}
}
func (*finalDPATransport) SetDeadline(time.Time) error      { return nil }
func (*finalDPATransport) SetReadDeadline(time.Time) error  { return nil }
func (*finalDPATransport) SetWriteDeadline(time.Time) error { return nil }

type finalDPAGate struct {
	inner            diam.Handler
	entered, release chan struct{}
}

func (h finalDPAGate) Unwrap() diam.Handler { return h.inner }
func (h finalDPAGate) ServeDIAM(c diam.Conn, m *diam.Message) {
	if m.Header.CommandCode == diam.DisconnectPeer && m.Header.CommandFlags&diam.RequestFlag == 0 {
		close(h.entered)
		<-h.release
	}
	h.inner.ServeDIAM(c, m)
}

// Final answer completion follows the reader
// boundary; a terminal error in the same read is already observable.
func TestClientFinalDPAReadOrdering(t *testing.T) {
	for _, together := range []bool{false, true} {
		for _, public := range []bool{false, true} {
			for _, heldWriter := range []bool{false, true} {
				t.Run(fmt.Sprintf("combined=%t/public=%t/heldWriter=%t", together, public, heldWriter), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						cli := newLivenessClient(t)
						cli.AcctApplicationID = nil
						cli.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}
						cli.WatchdogInterval = time.Hour
						cli.RetransmitInterval = time.Hour
						rw := &finalDPATransport{reads: make(chan finalDPARead, 3), writes: make(chan *diam.Message, 8), closed: make(chan struct{}), eofRead: make(chan struct{})}
						if heldWriter {
							writeRelease := make(chan struct{})
							rw.dprWriteRelease = writeRelease
							defer close(writeRelease)
						}
						entered, release := make(chan struct{}), make(chan struct{})
						unblock := sync.OnceFunc(func() { close(release) })
						defer unblock()
						dialed := make(chan protocolClientDialResult, 1)
						go func() {
							c, err := cli.dial(func(activity *watchdogActivity) (diam.Conn, error) {
								srv := cli.server("", "synthetic", nil, activity)
								srv.Handler = finalDPAGate{srv.Handler, entered, release}
								return srv.NewConn(rw)
							})
							dialed <- protocolClientDialResult{conn: c, err: err}
						}()
						cer := <-rw.writes
						cea := protocolClientCEA(cer, diam.Success)
						payload, err := cea.Serialize()
						if err != nil {
							t.Fatal(err)
						}
						rw.reads <- finalDPARead{data: payload}
						result := <-dialed
						if result.err != nil {
							t.Fatal(result.err)
						}
						defer result.conn.Close()
						if public {
							mustConnAs[diam.CloseNotifier](t, result.conn).CloseNotify()
							warm := finalDPAWatchdog(cli)
							payload, err = warm.Serialize()
							if err != nil {
								t.Fatal(err)
							}
							rw.reads <- finalDPARead{data: payload}
							if reply := <-rw.writes; reply.Header.CommandCode != diam.DeviceWatchdog {
								t.Fatal(reply.Header)
							}
						}
						disconnected := make(chan error, 1)
						go func() { disconnected <- cli.Handler.Disconnect(result.conn, DisconnectBusy, time.Hour) }()
						dpr := <-rw.writes
						if dpr.Header.CommandCode != diam.DisconnectPeer {
							t.Fatal(dpr.Header)
						}
						synctest.Wait()
						state := cli.Handler.acceptedCore(result.conn, nil, false)
						controls := state.snapshot().Controls()
						wantWriters := 0
						if heldWriter {
							wantWriters = 1
						}
						if len(controls) != 1 || controls[0].Command != diam.DisconnectPeer || !controls[0].Logical || controls[0].Writers != wantWriters {
							t.Fatalf("DPR writer state = %+v, want %d active writers", controls, wantWriters)
						}
						dpa := finalDPAnswer(dpr)
						payload, err = dpa.Serialize()
						if err != nil {
							t.Fatal(err)
						}
						read := finalDPARead{data: payload}
						if together {
							read.err = io.EOF
						}
						rw.reads <- read
						if !together {
							rw.reads <- finalDPARead{err: io.EOF}
						}
						<-entered
						synctest.Wait()
						before := "pending"
						var terminal error
						received := false
						select {
						case terminal = <-disconnected:
							before = fmt.Sprint(terminal)
							received = true
						default:
						}
						eof := false
						select {
						case <-rw.eofRead:
							eof = true
						default:
						}
						t.Logf("before DPA release: eof_read=%t Disconnect=%s", eof, before)
						unblock()
						if !received {
							terminal = <-disconnected
						}
						t.Logf("after DPA release: Disconnect=%v", terminal)
						if !public && !together {
							var want error
							if heldWriter {
								want = ErrDisconnectClosed
							}
							if eof || received || terminal != want {
								t.Fatalf("separate read direct ordering: eof=%t received=%t result=%v", eof, received, terminal)
							}
						} else {
							if !eof || !received || terminal != ErrDisconnectClosed {
								t.Fatalf("early EOF ordering: eof=%t received=%t result=%v", eof, received, terminal)
							}
						}
					})
				})
			}
		}
	}
}

func finalDPAWatchdog(cli *Client) *diam.Message {
	m := diam.NewRequest(diam.DeviceWatchdog, 0, cli.Dict)
	m.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	m.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	return m
}

func TestClientFinalDPAAfterPeerClose(t *testing.T) {
	for _, network := range []string{"tcp", "tls"} {
		for _, public := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/public=%t", network, public), func(t *testing.T) {
				cli := newLivenessClient(t)
				cli.AcctApplicationID = nil
				cli.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}
				cli.WatchdogInterval = time.Hour
				cli.RetransmitInterval = time.Hour
				peers := make(chan diam.Conn, 1)
				requests := make(chan *diam.Message, 2)
				warm := make(chan struct{}, 1)
				srv := diamtest.NewUnstartedServer(diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
					switch m.Header.CommandCode {
					case diam.CapabilitiesExchange:
						peers <- c
						if _, err := protocolClientCEA(m, diam.Success).WriteTo(c); err != nil {
							t.Error(err)
						}
					case diam.DisconnectPeer:
						requests <- m
					case diam.DeviceWatchdog:
						warm <- struct{}{}
					}
				}), cli.Dict)
				if network == "tls" {
					srv.StartTLS()
					cli.TLSConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- local test certificate
				} else {
					srv.Start()
				}
				defer srv.Close()
				entered, release := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				c, err := cli.dial(func(activity *watchdogActivity) (diam.Conn, error) {
					template := cli.server("tcp", srv.Addr, nil, activity)
					template.Handler = finalDPAGate{template.Handler, entered, release}
					if network == "tls" {
						return template.DialTLS("", "", 0)
					}
					return template.Dial(0)
				})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				peer := <-peers
				var gone <-chan struct{}
				if public {
					gone = mustConnAs[diam.CloseNotifier](t, c).CloseNotify()
					if _, err := finalDPAWatchdog(cli).WriteTo(peer); err != nil {
						t.Fatal(err)
					}
					protocolGenerationAwait(t, warm)
				}
				disconnected := make(chan error, 1)
				go func() { disconnected <- cli.Handler.Disconnect(c, DisconnectBusy, time.Hour) }()
				var dpr *diam.Message
				select {
				case dpr = <-requests:
				case <-time.After(10 * time.Second):
					t.Fatal("Disconnect did not send DPR")
				}
				state := cli.Handler.acceptedCore(c, nil, false)
				awaitReadCondition(t, func() bool {
					for _, control := range state.snapshot().Controls() {
						if control.Command == diam.DisconnectPeer && control.Logical && control.Writers == 0 {
							return true
						}
					}
					return false
				}, "DPR writer did not publish its result")
				dpa := finalDPAnswer(dpr)
				if _, err := dpa.WriteTo(peer); err != nil {
					t.Fatal(err)
				}
				protocolGenerationAwait(t, entered)
				closeDialTest(t, peer.Connection())
				if public {
					protocolGenerationAwait(t, gone)
					select {
					case err := <-disconnected:
						if !errors.Is(err, ErrDisconnectClosed) {
							t.Fatalf("Disconnect after public EOF = %v", err)
						}
					case <-time.After(10 * time.Second):
						t.Fatal("Disconnect did not observe public EOF")
					}
					unblock()
				} else {
					select {
					case err := <-disconnected:
						t.Fatalf("Disconnect overtook final DPA dispatch: %v", err)
					default:
					}
					unblock()
					select {
					case err := <-disconnected:
						if err != nil {
							t.Fatalf("final DPA did not complete Disconnect: %v", err)
						}
					case <-time.After(10 * time.Second):
						t.Fatal("Disconnect did not consume final DPA")
					}
				}
			})
		}
	}
}

func finalDPAnswer(request *diam.Message) *diam.Message {
	answer := request.Answer(diam.Success)
	answer.AddAVP(diam.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("peer.example")))
	answer.AddAVP(diam.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("example")))
	return answer
}

func TestClientDisconnectFirstObservesCompletedRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cli := newLivenessClient(t)
		cli.EnableWatchdog = false
		cli.RetransmitInterval = time.Hour
		cli.AcctApplicationID = nil
		cli.AuthApplicationID = []*diam.AVP{diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(4))}
		entered, release := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		cli.Handler.Handle("ALL", diam.HandlerFunc(func(diam.Conn, *diam.Message) { close(entered); <-release }))
		rw := &finalDPATransport{reads: make(chan finalDPARead, 3), writes: make(chan *diam.Message, 8), closed: make(chan struct{}), eofRead: make(chan struct{})}
		dialed := make(chan protocolClientDialResult, 1)
		go func() {
			c, err := cli.dial(func(activity *watchdogActivity) (diam.Conn, error) {
				srv := cli.server("", "synthetic", nil, activity)
				srv.MaxConcurrentHandlers = -1
				return srv.NewConn(rw)
			})
			dialed <- protocolClientDialResult{conn: c, err: err}
		}()
		cea, err := protocolClientCEA(<-rw.writes, diam.Success).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		rw.reads <- finalDPARead{data: cea}
		result := <-dialed
		if result.err != nil {
			t.Fatal(result.err)
		}
		defer result.conn.Close()
		message, err := diam.NewMessage(999, 0, 4, 123, 456, cli.Dict).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		rw.reads <- finalDPARead{data: message}
		<-entered
		rw.reads <- finalDPARead{err: io.EOF}
		<-rw.eofRead
		synctest.Wait()
		if result.conn.Closed() {
			t.Fatal("terminal read closed the generation before its callback drained")
		}
		disconnected := make(chan error, 1)
		go func() { disconnected <- cli.Handler.Disconnect(result.conn, DisconnectBusy, time.Hour) }()
		synctest.Wait()
		select {
		case err := <-disconnected:
			if !errors.Is(err, ErrDisconnectClosed) {
				t.Fatalf("first Disconnect after EOF = %v", err)
			}
		default:
			t.Error("first Disconnect missed the completed transport read")
		}
		select {
		case message := <-rw.writes:
			t.Fatalf("Disconnect wrote after terminal read: %+v", message.Header)
		default:
		}
		unblock()
	})
}
