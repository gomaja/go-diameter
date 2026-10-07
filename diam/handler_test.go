package diam

import (
	"errors"
	"testing"
)

type unwrapHandler struct{ Handler }

func (w unwrapHandler) Unwrap() Handler { return w.Handler }

type opaqueHandler struct{ h Handler }

func (w opaqueHandler) ServeDIAM(c Conn, m *Message) { w.h.ServeDIAM(c, m) }

func TestHandlerAs(t *testing.T) {
	inner := newRecordingMessageErrorHandler()
	for _, tc := range []struct {
		name string
		h    Handler
		want MessageErrorHandler
	}{
		{"nil", nil, nil}, {"direct", inner, inner}, {"one", unwrapHandler{inner}, inner},
		{"two", unwrapHandler{unwrapHandler{inner}}, inner}, {"opaque", opaqueHandler{inner}, nil},
		{"nil unwrap", unwrapHandler{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := HandlerAs[MessageErrorHandler](tc.h)
			if got != tc.want || ok != (tc.want != nil) {
				t.Fatalf("got %v, %v; want %v", got, ok, tc.want)
			}
		})
	}
}
func TestMuxMessageErrorUnsupported(t *testing.T) {
	if err := NewServeMux().HandleMessageError(nil, nil, nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}
