package diam

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

func TestCERRenewalInheritsReadAheadEOF(t *testing.T) {
	for _, mode := range []int{0, 2, -1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, remote := net.Pipe()
				raw := &restartTransport{Conn: local, reads: make(chan restartRead), closed: make(chan struct{})}
				admitted := make(chan struct{})
				retiring, resumeRetirement := make(chan struct{}), make(chan struct{})
				business := make(chan Conn, 1)
				notified, release, abort := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var open atomic.Bool
				srv := &Server{RenewAcceptedCER: true, MaxConcurrentHandlers: mode}
				srv.Handler = &generationHandler{
					accept: func(c Conn) func() {
						mustConnAs[CloseNotifier](t, c).CloseNotify()
						return nil
					},
					eligible: func(Conn) bool { return open.Load() },
					retire: func(Conn, RetirementReason) error {
						close(retiring)
						<-resumeRetirement
						return nil
					},
					handle: func(c Conn, m *Message) {
						releaseAdmission := m.BeginDispatch()
						defer releaseAdmission()
						if m.Header.CommandCode == CapabilitiesExchange {
							if mustConnAs[ConnLifecycle](t, c).Generation() == 1 {
								open.Store(true)
								close(admitted)
							}
							return
						}
						business <- c
						select {
						case <-mustConnAs[CloseNotifier](t, c).CloseNotify():
							close(notified)
						case <-abort:
							return
						}
						<-release
					},
				}
				c := srv.newConn(raw)
				c.accepted = true
				if !srv.trackConn(c) {
					t.Fatal("track connection")
				}
				served := make(chan struct{})
				go func() { c.serve(); close(served) }()
				raw.reads <- restartRead{data: cerPayload(t)}
				<-admitted
				request, err := NewRequest(DeviceWatchdog, 0, nil).Serialize()
				if err != nil {
					t.Fatal(err)
				}
				// The physical reader can fill its read-ahead buffer, then see
				// EOF while the retirement hook holds successor publication.
				data := append(append([]byte(nil), cerPayload(t)...), request...)
				raw.reads <- restartRead{data: data}
				<-retiring
				raw.reads <- restartRead{err: io.EOF}
				synctest.Wait()
				close(resumeRetirement)
				next := <-business
				synctest.Wait()
				select {
				case <-notified:
				default:
					t.Error("successor lost physical EOF: decoded callback is waiting for CloseNotify")
				}
				if mustConnAs[ConnLifecycle](t, next).Generation() != 2 {
					t.Error("read-ahead application message did not reach successor")
				}
				if next.Closed() {
					t.Error("EOF published Closed before successor callback returned")
				}
				select {
				case <-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, next).DispatchDone():
					t.Error("EOF completed dispatch before successor callback returned")
				default:
				}
				// Abort also releases the callback on the regression path, so
				// missing notification produces an assertion, not a deadlock.
				close(abort)
				close(release)
				<-served
				if !next.Closed() {
					t.Error("reader completion did not publish Closed")
				}
				select {
				case <-mustConnAs[interface{ DispatchDone() <-chan struct{} }](t, next).DispatchDone():
				default:
					t.Error("reader completion did not finish successor dispatch")
				}
				_ = remote.Close()
			})
		})
	}
}
