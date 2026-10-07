package diam

import (
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

func TestServeMuxRegistrationPanics(t *testing.T) {
	h := HandlerFunc(func(Conn, *Message) {})
	idx := CommandIndex{0, CapabilitiesExchange, true}
	for _, tc := range []struct {
		name     string
		register func(*ServeMux)
	}{
		{"typed nil", func(m *ServeMux) { m.Handle("CER", HandlerFunc(nil)) }},
		{"typed nil index", func(m *ServeMux) { m.HandleIdx(idx, HandlerFunc(nil)) }},
		{"nil", func(m *ServeMux) { m.Handle("CER", nil) }},
		{"nil func", func(m *ServeMux) { m.HandleFunc("CER", nil) }},
		{"empty", func(m *ServeMux) { m.Handle("", h) }},
		{"duplicate name", func(m *ServeMux) { m.Handle("CER", h); m.Handle("CER", h) }},
		{"duplicate index", func(m *ServeMux) { m.HandleIdx(idx, h); m.HandleIdx(idx, h) }},
		{"nil index", func(m *ServeMux) { m.HandleIdx(idx, nil) }},
		{"ALL then index", func(m *ServeMux) { m.Handle("ALL", h); m.HandleIdx(ALL_CMD_INDEX, h) }},
		{"index then ALL", func(m *ServeMux) { m.HandleIdx(ALL_CMD_INDEX, h); m.Handle("ALL", h) }},
		{"package", func(m *ServeMux) {
			old := DefaultServeMux
			DefaultServeMux = m
			defer func() { DefaultServeMux = old }()
			Handle("CER", h)
			Handle("CER", h)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("registration did not panic")
				}
			}()
			tc.register(NewServeMux())
		})
	}
}

func TestServeMuxHandlerIndexFirst(t *testing.T) {
	mux := NewServeMux()
	called := ""
	mux.Handle("ALL", HandlerFunc(func(Conn, *Message) { called = "all" }))
	mux.HandleIdx(CommandIndex{999999, 999999, true}, HandlerFunc(func(Conn, *Message) { called = "index" }))
	m := NewRequest(999999, 999999, dict.New(dict.Base))
	mux.ServeDIAM(nil, m)
	if called != "index" {
		t.Fatalf("unknown command route=%q", called)
	}
	empty := NewServeMux()
	if h, ok := empty.Handler(m); ok || h != nil {
		t.Fatal("empty mux matched")
	}
}

func TestServeMuxShortNameAcrossApplications(t *testing.T) {
	dp := dict.New(dict.S6a, dict.Sh)
	mux := NewServeMux()
	called := ""
	mux.Handle("PUR", HandlerFunc(func(Conn, *Message) { called = "name" }))
	for _, tc := range []struct{ app, cmd uint32 }{{16777251, 321}, {16777217, 307}} {
		m := NewRequest(tc.cmd, tc.app, dp)
		called = ""
		mux.ServeDIAM(nil, m)
		if called != "name" {
			t.Fatalf("PUR %d/%d did not match name", tc.app, tc.cmd)
		}
	}
	mux.HandleIdx(CommandIndex{16777251, 321, true}, HandlerFunc(func(Conn, *Message) { called = "s6a" }))
	for _, tc := range []struct {
		app, cmd uint32
		want     string
	}{{16777251, 321, "s6a"}, {16777217, 307, "name"}} {
		called = ""
		mux.ServeDIAM(nil, NewRequest(tc.cmd, tc.app, dp))
		if called != tc.want {
			t.Fatalf("PUR %d/%d = %q, want %q", tc.app, tc.cmd, called, tc.want)
		}
	}
}
