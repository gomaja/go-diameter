package diam

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

type handshakeBoundaryReader struct {
	io.Reader
	done  <-chan struct{}
	reads atomic.Int32
	early atomic.Bool
}

func (r *handshakeBoundaryReader) Read(b []byte) (int, error) {
	r.reads.Add(1)
	select {
	case <-r.done:
	default:
		r.early.Store(true)
		<-r.done
	}
	return r.Reader.Read(b)
}

func TestCloseNotifyWaitsForTLSHandshake(t *testing.T) {
	for _, registration := range []string{"before-handshake", "during-handshake"} {
		t.Run(registration, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, remote := net.Pipe()
				verifying, finishVerification := make(chan struct{}), make(chan struct{})
				allowVerification := sync.OnceFunc(func() { close(finishVerification) })
				entered, release := make(chan struct{}), make(chan struct{})
				allowCallback := sync.OnceFunc(func() { close(release) })
				client := tls.Client(local, &tls.Config{
					InsecureSkipVerify: true, // The local handshake uses an ephemeral certificate.
					MinVersion:         tls.VersionTLS13,
					VerifyConnection: func(tls.ConnectionState) error {
						close(verifying)
						<-finishVerification
						return nil
					},
				})
				peer := tls.Server(remote, &tls.Config{Certificates: []tls.Certificate{generationCertificate(t)}, MinVersion: tls.VersionTLS13})
				peerHandshake := make(chan error, 1)
				go func() { peerHandshake <- peer.Handshake() }()
				srv := &Server{OnNewConnection: func(Conn) { close(entered); <-release }}
				var c *conn
				if registration == "before-handshake" {
					c = srv.newConn(client)
				} else {
					public, err := srv.NewConn(client)
					if err != nil {
						t.Fatal(err)
					}
					c = public.(*response).conn
					<-verifying
				}
				defer func() {
					allowVerification()
					allowCallback()
					_ = remote.Close()
					_ = local.Close()
					<-c.owner.done
				}()
				c.sr.Lock()
				observed := &handshakeBoundaryReader{Reader: c.sr.r, done: c.handshakeDone}
				c.sr.r = observed
				c.sr.Unlock()
				gone := c.writer.CloseNotify()
				if registration == "before-handshake" {
					go c.serve()
					<-verifying
				}
				synctest.Wait()
				if observed.reads.Load() != 0 {
					t.Error("application read started while the TLS handshake was held")
				}
				allowVerification()
				<-entered
				if err := <-peerHandshake; err != nil {
					t.Fatalf("peer TLS handshake: %v", err)
				}
				synctest.Wait()
				if observed.early.Load() {
					t.Error("application read started before the handshake completion boundary")
				}
				if observed.reads.Load() != 1 {
					t.Errorf("application reads while OnNewConnection is held = %d, want 1", observed.reads.Load())
				}
				if err := remote.Close(); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				select {
				case <-gone:
				default:
					t.Error("public subscriber missed peer loss while OnNewConnection was held")
				}
				if c.writer.Closed() {
					t.Error("connection closed before OnNewConnection returned")
				}
				allowCallback()
				<-c.owner.done
			})
		})
	}
}
