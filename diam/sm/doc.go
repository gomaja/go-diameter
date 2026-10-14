// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package sm provides diameter state machines for clients and servers.
//
// It currently handles CER/CEA handshakes, and automatic DWR/DWA. Peers
// that pass the handshake get metadata associated to their connection.
// See the smpeer sub-package for details on the metadata.
//
// StateMachine and peer.Manager ignore a base CER on a connection whose
// capabilities exchange has completed: one Warn log, no answer, and the
// connection stays open. RFC 6733 §5.6 has no row for this event; R-Conn-CER
// concerns a CER on a new connection (§5.6.1). OnProtocolError reports
// ProtocolUnexpectedMessage with Closing=false and ProtocolReplyNone.
// With diam.Server.RenewAcceptedCER enabled, StateMachine instead renews an
// accepted connection on that CER when it is admitted, live and not Closing;
// peer.Manager does the same for the peer's current active responder.
//
// Settings.EnableWatchdog opts accepted connections into RFC 3539 §3.4.1 and
// Appendix A supervision after a success CEA and OnHandshake. Client.EnableWatchdog
// independently supervises dialed connections. Both remain opt-in; conforming
// deployments should enable them (RFC 6733 §5.5.3).
//
// Twinit defaults to 30 seconds, has a 6-second minimum, and each timer reset
// adds ±2 seconds of jitter. Incoming messages reset Tw; outgoing traffic does
// not. Only one DWR may be pending. Silence produces a DWR at the first expiry,
// SUSPECT at the second, and DOWN with transport closure at the third. The
// watchdog stops when DPR enters Closing (RFC 6733 §5.6); accepted supervisors
// then ignore DWA and activity and emit no further watchdog events.
// Supervised DWAs are consumed before user "DWA" routes. After supervision
// ends, late DWAs follow normal dispatch and, without a matching route, are
// logged as unhandled answers. After peer FIN, DispatchDone
// waits for in-flight concurrent handlers, so the watchdog may continue to
// run and report events for that departing peer until they finish.
//
// OnWatchdogConnEvent identifies the accepted connection. SUSPECT reports
// failover, leaving request routing to the application (RFC 6733 §5.5.4).
// StateMachine does not reconnect or keep a peer control block across connections;
// use peer.Manager for managed peers and RFC 3539 Appendix A REOPEN validation.
// Choose Twinit to tolerate handler latency (RFC 3539 §3.4): saturated concurrent
// dispatch can delay reading DWAs. Server.WriteTimeout bounds socket writes,
// including DWR; it does not bound callbacks or custom Conn wrappers. A blocked
// DWR write delays watchdog progress, DWA crediting and Disconnect/DPR stop,
// but ordinary inbound dispatch can continue. OnWatchdogConnEvent must not
// call Disconnect synchronously or wait for any inbound message on that
// connection; both can deadlock. Conn wrappers must keep the same identity
// across messages.
//
// Settings.OnProtocolError reports handled protocol conditions without changing
// their answers, connection policy or logs (RFC 6733 §§5.6, 7). The callback runs
// synchronously after its owner's handling attempt and logs, on that handler,
// reader or timer goroutine. peer.Manager honours the same hook, independently
// of OnPeerEvent, after enqueueing any answer. ProtocolReplyWritten and
// ProtocolReplyQueued describe local progress, not receipt by the peer.
// Callbacks may overlap on one connection and must return promptly: blocking
// delays their worker. Panics are recovered and logged through Conn.Logger.
// No queue, worker or retained backlog is created for the hook.
//
// Events retain copied header and stream metadata and a normalized typed error,
// with no message, AVPs or parser error graph. These values are safe to keep;
// retaining Conn keeps that connection object alive. Closing records the
// handling decision, not a live state query. Timer events have no header.
// A callback may call Conn.Close, but must not synchronously call Disconnect,
// Manager.Close, shutdown/wait operations or wait for later inbound messages.
//
// Accepted renewal through Server.OnConnectionRestart creates a fresh Conn.
// An in-flight protocol notification keeps the generation's original Conn and
// may run after its CloseNotify or retirement; CloseNotify is not a callback
// drain barrier. A successful CER renewal emits no protocol error. Configure
// OnProtocolError before use; concurrent Settings mutation is unsupported.
package sm
