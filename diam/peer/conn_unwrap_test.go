package peer

import (
	"testing"
	"testing/synctest"

	"github.com/gomaja/go-diameter/diam"
)

type unwrapTestConn struct{ diam.Conn }

func (c unwrapTestConn) Unwrap() diam.Conn { return c.Conn }

type dispatchTestConn struct {
	*fakeConn
	dispatched chan struct{}
}

func (c *dispatchTestConn) DispatchDone() <-chan struct{} { return c.dispatched }

func TestSessionWatchWrappedConn(t *testing.T) {
	for _, dispatch := range []bool{false, true} {
		for _, depth := range []int{0, 1, 2, -1} {
			t.Run(fmtConnCase(dispatch, depth), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					base := newFakeConn()
					defer base.Close()
					var c diam.Conn = base
					dispatched := make(chan struct{})
					if dispatch {
						c = &dispatchTestConn{base, dispatched}
					}
					for range depth {
						c = unwrapTestConn{c}
					}
					if depth < 0 {
						c = struct{ diam.Conn }{c}
					}
					m := &Manager{sessions: make(map[diam.Conn]*session)}
					s := &session{m: m, c: c, closed: make(chan struct{})}
					m.sessions[c] = s
					m.wg.Add(1)
					done := make(chan struct{})
					go func() { s.watch(); close(done) }()
					synctest.Wait()
					base.Close()
					synctest.Wait()
					if dispatch || depth < 0 {
						select {
						case <-done:
							t.Fatal("watch returned before DispatchDone or explicit close")
						default:
						}
					}
					if dispatch {
						close(dispatched)
						synctest.Wait()
					}
					if depth < 0 {
						select {
						case <-done:
							t.Fatal("opaque wrapper exposed optional interface")
						default:
						}
						s.close()
					}
					synctest.Wait()
					select {
					case <-done:
					default:
						s.close()
						t.Fatal("watch did not observe wrapped connection closure")
					}
					if len(m.sessions) != 0 {
						t.Fatal("session was not unregistered")
					}
				})
			})
		}
	}
}
func fmtConnCase(dispatch bool, depth int) string {
	names := map[int]string{-1: "opaque", 0: "direct", 1: "one", 2: "two"}
	if dispatch {
		return "dispatch/" + names[depth]
	}
	return "close/" + names[depth]
}

type closeInterceptConn struct {
	diam.Conn
	closed <-chan struct{}
}

func (c closeInterceptConn) Unwrap() diam.Conn            { return c.Conn }
func (c closeInterceptConn) CloseNotify() <-chan struct{} { return c.closed }

func TestSessionWatchCloseNotifierInterceptsInnerDispatchDone(t *testing.T) {
	for _, depth := range []int{0, 1, 2} {
		t.Run(fmtConnCase(false, depth), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				base := newFakeConn()
				defer base.Close()
				innerDone := make(chan struct{})
				outerDone := make(chan struct{})
				var c diam.Conn = closeInterceptConn{&dispatchTestConn{base, innerDone}, outerDone}
				for range depth {
					c = unwrapTestConn{c}
				}
				m := &Manager{sessions: make(map[diam.Conn]*session)}
				s := &session{m: m, c: c, closed: make(chan struct{})}
				m.sessions[c] = s
				m.wg.Add(1)
				done := make(chan struct{})
				go func() { s.watch(); close(done) }()
				synctest.Wait()
				close(outerDone)
				synctest.Wait()
				select {
				case <-done:
				default:
					s.close()
					synctest.Wait()
					t.Fatal("outer CloseNotify was ignored in favor of inner DispatchDone")
				}
				if len(m.sessions) != 0 {
					t.Fatal("session not unregistered")
				}
			})
		})
	}
}
