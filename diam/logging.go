// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"log/slog"
	"net"
	"runtime"
)

// panicStackSize bounds the stack recorded with a recovered handler panic.
// It is the size net/http's conn.serve uses for the same record.
const panicStackSize = 64 << 10

// Attribute keys of the records Server writes.
const (
	logKeyNetwork    = "network"
	logKeyLocalAddr  = "local_addr"
	logKeyRemoteAddr = "remote_addr"
	logKeyError      = "error"
	logKeyReadError  = "read_error"
	logKeyPanic      = "panic"
	logKeyStack      = "stack"
	logKeyRetryIn    = "retry_in"
)

// logger returns the logger that receives srv's records. A nil Logger is
// resolved to slog.Default on every call, so a slog.SetDefault made after
// the Server was configured still applies.
func (srv *Server) logger() *slog.Logger {
	if srv.Logger != nil {
		return srv.Logger
	}
	return slog.Default()
}

// log writes a record about c. It adds the connection's network and
// addresses to attrs and passes the connection's Context to the handler.
func (c *conn) log(level slog.Level, msg string, attrs ...slog.Attr) {
	l := c.server.logger()
	ctx := c.writer.Context()
	if !l.Enabled(ctx, level) {
		return
	}
	l.LogAttrs(ctx, level, msg, append(addrAttrs(c.rwc.LocalAddr(), c.rwc.RemoteAddr()), attrs...)...)
}

// logPanic records a panic recovered from a handler or from the read loop,
// with the stack of the goroutine that recovered it.
func (c *conn) logPanic(v any) {
	stack := make([]byte, panicStackSize)
	stack = stack[:runtime.Stack(stack, false)]
	c.log(slog.LevelError, "diam: panic serving connection",
		slog.Any(logKeyPanic, v), slog.String(logKeyStack, string(stack)))
}

// addrAttrs describes a connection or listener by its network and addresses.
// A nil address is left out.
func addrAttrs(local, remote net.Addr) []slog.Attr {
	attrs := make([]slog.Attr, 0, 3)
	switch {
	case local != nil:
		attrs = append(attrs, slog.String(logKeyNetwork, local.Network()))
	case remote != nil:
		attrs = append(attrs, slog.String(logKeyNetwork, remote.Network()))
	}
	if local != nil {
		attrs = append(attrs, slog.String(logKeyLocalAddr, local.String()))
	}
	if remote != nil {
		attrs = append(attrs, slog.String(logKeyRemoteAddr, remote.String()))
	}
	return attrs
}

// Logger implements Conn.
func (w *response) Logger() *slog.Logger {
	attrs := addrAttrs(w.conn.rwc.LocalAddr(), w.conn.rwc.RemoteAddr())
	args := make([]any, len(attrs))
	for i, a := range attrs {
		args[i] = a
	}
	return w.conn.server.logger().With(args...)
}

// LogValue describes only the header. AVPs, including subscriber values, are
// deliberately excluded. A nil message or header produces an empty group.
func (m *Message) LogValue() slog.Value {
	if m == nil || m.Header == nil {
		return slog.GroupValue()
	}
	h := m.Header
	attrs := []slog.Attr{}
	if cmd, err := m.Dictionary().FindCommand(h.ApplicationID, h.CommandCode); err == nil {
		name := cmd.Short + "A"
		if h.CommandFlags&RequestFlag != 0 {
			name = cmd.Short + "R"
		}
		attrs = append(attrs, slog.String("command", name))
	}
	return slog.GroupValue(append(attrs,
		slog.Uint64("application_id", uint64(h.ApplicationID)),
		slog.Uint64("command_code", uint64(h.CommandCode)),
		slog.Bool("request", h.CommandFlags&RequestFlag != 0),
		slog.Uint64("hop_by_hop_id", uint64(h.HopByHopID)),
		slog.Uint64("end_to_end_id", uint64(h.EndToEndID)))...)
}
