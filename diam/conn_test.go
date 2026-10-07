package diam

import "testing"

type unwrapConn struct{ Conn }

func (w unwrapConn) Unwrap() Conn { return w.Conn }

type opaqueConn struct{ Conn }
type notifyingConn struct {
	Conn
	done chan struct{}
}

func (c *notifyingConn) CloseNotify() <-chan struct{}  { return c.done }
func (c *notifyingConn) DispatchDone() <-chan struct{} { return c.done }

type interceptingConn struct {
	unwrapConn
	done chan struct{}
}

func (c *interceptingConn) CloseNotify() <-chan struct{} { return c.done }

func TestConnAs(t *testing.T) {
	inner := &notifyingConn{done: make(chan struct{})}
	outer := &interceptingConn{unwrapConn{inner}, make(chan struct{})}
	for _, tc := range []struct {
		name string
		c    Conn
		want CloseNotifier
	}{
		{"nil", nil, nil}, {"direct", inner, inner}, {"one", unwrapConn{inner}, inner},
		{"two", unwrapConn{unwrapConn{inner}}, inner}, {"opaque", opaqueConn{inner}, nil},
		{"nil unwrap", unwrapConn{}, nil}, {"intercept", outer, outer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ConnAs[CloseNotifier](tc.c)
			if got != tc.want || ok != (tc.want != nil) {
				t.Fatalf("ConnAs = %v, %v; want %v", got, ok, tc.want)
			}
		})
	}
	if got, ok := ConnAs[*notifyingConn](unwrapConn{inner}); !ok || got != inner {
		t.Fatal("concrete type not found")
	}
	if got, ok := ConnAs[interface{ DispatchDone() <-chan struct{} }](unwrapConn{unwrapConn{inner}}); !ok || got.DispatchDone() != inner.done {
		t.Fatal("DispatchDone not found")
	}
	if got, ok := ConnAs[CloseNotifier](outer.Unwrap()); !ok || got != inner {
		t.Fatal("interceptor cannot delegate")
	}
}

func mustConnAs[T any](t *testing.T, c Conn) T {
	t.Helper()
	v, ok := ConnAs[T](c)
	if !ok {
		t.Fatalf("connection %T does not expose %T", c, (*T)(nil))
	}
	return v
}
