// Copyright 2013-2020 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"bytes"
	"container/heap"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gomaja/go-sctp"
)

const (
	// MaxInboundSCTPStreams - max inbound streams default for new connections.
	// RFC 9260 §6.5 defines SCTP streams; this value is the association
	// request default used for new Diameter connections.
	MaxInboundSCTPStreams = 16

	// MaxOutboundSCTPStreams - max outbound streams default for new connections.
	MaxOutboundSCTPStreams = MaxInboundSCTPStreams

	// DiameterPPID - SCTP Payload Protocol Identifier for Diameter.
	// RFC 6733 §2.1 runs Diameter over SCTP; RFC 9260 §3.3.1 carries the
	// PPID as upper-layer metadata and RFC 6458 §5.3.4 defines SCTP_SNDINFO
	// byte-order handling.
	DiameterPPID uint32 = 46
)

type sctpDialer struct {
	LocalAddr *sctp.Addr
	Timeout   time.Duration
}

// sctpSingleStreamDialer - SCTP Dialer for stream unaware applications.
type sctpSingleStreamDialer sctpDialer

type sctpListener struct {
	*sctp.Listener
}

type sctpMessageReceiver interface {
	RecvMsg([]byte) (int, sctp.MsgInfo, error)
}

// recvSCTPData consumes notifications, which share the SCTP receive queue
// with data (RFC 6458 §6), without presenting them as Diameter bytes.
func recvSCTPData(r sctpMessageReceiver, b []byte) (int, sctp.MsgInfo, error) {
	for {
		n, info, err := r.RecvMsg(b)
		if err != nil || !info.Notification {
			return n, info, err
		}
	}
}

// diameterSCTPConfig applies the association defaults before dial or listen.
// RFC 6458 §§8.1.3, 8.1.5, 8.1.19 and 8.1.31 define these socket options;
// RFC 6733 §2.1.1 assigns Diameter PPID 46.
func diameterSCTPConfig() *sctp.Config {
	return &sctp.Config{
		InitMsg:        sctp.InitMsg{OutStreams: MaxOutboundSCTPStreams, MaxInStreams: MaxInboundSCTPStreams},
		NoDelay:        new(true),
		DelayedSACK:    &sctp.DelayedSACK{Frequency: 1},
		DefaultSndInfo: &sctp.SndInfo{PPID: DiameterPPID},
	}
}

type streamBuffer struct {
	*bytes.Buffer
	stream uint
	idx    int
}

type streams struct {
	streamMap  map[uint]*streamBuffer
	streamHeap []*streamBuffer
}

// Go Heap interface implementation
func (pq *streams) Len() int {
	return len(pq.streamHeap)
}

func (pq *streams) Less(i, j int) bool {
	return pq.streamHeap[i].Len() > pq.streamHeap[j].Len()
}

func (pq *streams) Swap(i, j int) {
	pq.streamHeap[i], pq.streamHeap[j] = pq.streamHeap[j], pq.streamHeap[i]
	pq.streamHeap[i].idx = i
	pq.streamHeap[j].idx = j
}

func (pq *streams) Push(x interface{}) {
	sb := x.(*streamBuffer)
	if _, ok := pq.streamMap[sb.stream]; ok {
		panic("pushing an existing stream " + strconv.Itoa(int(sb.stream)))
	}
	sb.idx = len(pq.streamHeap)
	pq.streamHeap = append(pq.streamHeap, sb)
	if pq.streamMap == nil {
		pq.streamMap = map[uint]*streamBuffer{sb.stream: sb}
	} else {
		pq.streamMap[sb.stream] = sb
	}
}

func (pq *streams) Pop() interface{} {
	n := len(pq.streamHeap)
	sb := pq.streamHeap[n-1]
	delete(pq.streamMap, sb.stream)
	pq.streamHeap = pq.streamHeap[0 : n-1]
	sb.idx = -1
	return sb
}

// SCTPConn - MutistreamConn implementation for SCTP.
type SCTPConn struct {
	*sctp.Conn

	streamBuffMu sync.Mutex
	s            *streams
	mu           sync.RWMutex
	currStream   uint
	wmu          sync.RWMutex
	writerStream uint
	errorHandler MutistreamConnErrorHandler
}

// NewSCTPConn wraps a go-sctp connection the caller opened as a
// MultistreamConn. It applies the two latency settings that Dial, Listen and
// MultistreamListen give every association through their sctp.Config:
// SCTP_NODELAY (RFC 6458 §8.1.5), so small Diameter messages are sent at
// once instead of being coalesced, and a delayed-SACK frequency of 1
// (RFC 6458 §8.1.19), so every packet is acknowledged without delay.
//
// A failure to apply either setting is returned, as go-sctp returns it, and
// sctpConn is left open for the caller to close. Settings fixed when the
// association is set up, such as its stream counts (RFC 6458 §8.1.3), are
// chosen by whoever opens sctpConn.
func NewSCTPConn(sctpConn *sctp.Conn) (MultistreamConn, error) {
	if sctpConn == nil {
		return nil, errors.New("diam: nil SCTP connection")
	}
	if err := sctpConn.SetNoDelay(true); err != nil {
		return nil, fmt.Errorf("diam: set SCTP_NODELAY: %w", err)
	}
	if err := sctpConn.SetDelayedSACK(&sctp.DelayedSACK{Frequency: 1}); err != nil {
		return nil, fmt.Errorf("diam: set SCTP delayed SACK: %w", err)
	}
	return newSCTPConn(sctpConn), nil
}

// newSCTPConn wraps a connection opened from diameterSCTPConfig without
// setting any option again. go-sctp applied the Config before the socket
// connected or listened and failed the call if it could not, and an
// accepted socket inherits the listening socket's settings (go-sctp
// Listener documentation).
func newSCTPConn(sctpConn *sctp.Conn) *SCTPConn {
	return &SCTPConn{Conn: sctpConn, s: &streams{}, currStream: InvalidStreamID, writerStream: InvalidStreamID}
}

// ReadAny reads data from any association's stream (if available).
// Returns number of bytes read and the stream number.
func (msc *SCTPConn) ReadAny(b []byte) (n int, stream uint, err error) {
	// First see if we can consume an existing, previously received buffer
	msc.streamBuffMu.Lock()
	// Consume the longest buffer first
	if msc.s.Len() > 0 && msc.s.streamHeap[0].Len() > 0 {
		sb := msc.s.streamHeap[0]
		n, err = sb.Read(b)
		stream = sb.stream
		heap.Fix(msc.s, 0)
		msc.streamBuffMu.Unlock()
		return
	}
	msc.streamBuffMu.Unlock()
	var info sctp.MsgInfo
	n, info, err = recvSCTPData(msc.Conn, b)
	if n < 0 {
		n = 0
	}
	stream = uint(info.Rcv.Stream)
	// shortcut for non empty stream buffer
	n, err = msc.verifyStreamBuff(b, n, stream, err)
	if err != nil {
		hptr := atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&msc.errorHandler)))
		if hptr != nil {
			(*(*MutistreamConnErrorHandler)(unsafe.Pointer(&hptr)))(msc, err)
		}
	}
	return
}

// SetErrorHandler sets reader error notification handler,
// it'll be called on any read IO error for the connection.
func (msc *SCTPConn) SetErrorHandler(h MutistreamConnErrorHandler) {
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&msc.errorHandler)), *(*unsafe.Pointer)(unsafe.Pointer(&h)))
}

// ReadStream reads data from the specified association's stream.
func (msc *SCTPConn) ReadStream(b []byte, stream uint) (n int, err error) {
	var info sctp.MsgInfo
	var currStream uint
	msc.streamBuffMu.Lock()
	for {
		// First see if we can consume an existing, previously received stream buffer
		if sb, ok := msc.s.streamMap[stream]; ok && sb.Len() > 0 {
			n, err = sb.Read(b)
			heap.Fix(msc.s, sb.idx)
			msc.streamBuffMu.Unlock()
			return
		}

		msc.streamBuffMu.Unlock()
		n, info, err = recvSCTPData(msc.Conn, b)
		if n <= 0 {
			return 0, err
		}

		currStream = uint(info.Rcv.Stream)
		// Keep byte reassembly across SCTP messages on each stream.
		if currStream == stream {
			// A concurrent read may have buffered data while RecvMsg was waiting.
			return msc.verifyStreamBuff(b, n, stream, err)
		}
		rb := b[0:n]
		msc.streamBuffMu.Lock()
		msc.bufferStreamData(rb, currStream)
	}
}

// ReadAtLeast reads into b from the stream until it has read at least min bytes.
// It returns the number of bytes copied and an error if fewer bytes were read.
// If min is greater than the length of buf, ReadAtLeast returns ErrShortBuffer.
func (msc *SCTPConn) ReadAtLeast(buf []byte, min int, strm uint) (n int, stream uint, err error) {
	if len(buf) < min {
		return 0, InvalidStreamID, io.ErrShortBuffer
	}
	var nn int
	if strm == InvalidStreamID {
		nn, stream, err = msc.ReadAny(buf)
		n += nn
	} else {
		stream = strm
	}
	for n < min && err == nil {
		nn, err = msc.ReadStream(buf[n:], stream)
		n += nn
	}
	if n >= min {
		err = nil
	} else if n > 0 && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}

// verifyStreamBuff checks is there is a ready buffered data for the stream already,
// pipes b through the same buffer if there is and re-reads b from the beginning of the buffer.
func (msc *SCTPConn) verifyStreamBuff(b []byte, n int, stream uint, currErr error) (int, error) {
	msc.streamBuffMu.Lock()
	defer msc.streamBuffMu.Unlock()
	if sb, ok := msc.s.streamMap[stream]; ok && sb.Len() > 0 {
		sb.Write(b[0:n])
		heap.Fix(msc.s, sb.idx)
		return sb.Read(b)
	}
	return n, currErr
}

// bufferStreamData buffers b into the corresponding stream buffer.
func (msc *SCTPConn) bufferStreamData(b []byte, stream uint) {
	sb, ok := msc.s.streamMap[stream]
	if ok {
		sb.Write(b)
		heap.Fix(msc.s, sb.idx)
	} else {
		sb = &streamBuffer{Buffer: new(bytes.Buffer), stream: stream}
		sb.Write(b)
		heap.Push(msc.s, sb)
	}
}

// WriteStream writes data to the association's stream.
func (msc *SCTPConn) WriteStream(b []byte, stream uint) (int, error) {
	info := &sctp.SndInfo{PPID: DiameterPPID}
	if stream != InvalidStreamID {
		info.Stream = uint16(stream)
	}
	return msc.SendMsg(b, sctp.SendOptions{Info: info})
}

// CurrentStream returns the last stream read by Read 'adaptor'.
func (msc *SCTPConn) CurrentStream() uint {
	msc.mu.RLock()
	defer msc.mu.RUnlock()
	return msc.currStream
}

// ResetCurrentStream resets current read stream so the next Read adaptor call will read from any stream.
func (msc *SCTPConn) ResetCurrentStream() {
	msc.mu.Lock()
	msc.currStream = InvalidStreamID
	msc.mu.Unlock()
}

// SetCurrentStream sets current read stream so the next Read adaptor call will be forced to read from it.
func (msc *SCTPConn) SetCurrentStream(stream uint) uint {
	msc.mu.Lock()
	stream, msc.currStream = msc.currStream, stream
	msc.mu.Unlock()
	return stream
}

// CurrentWriterStream returns the stream that the next call to Write adaptor will be used for writing.
func (msc *SCTPConn) CurrentWriterStream() uint {
	msc.wmu.RLock()
	defer msc.wmu.RUnlock()
	return msc.writerStream
}

// ResetWriterStream resets current write stream so the next Write adaptor call
// will use either the current Read stream (if set) or the protocol specific
// default stream to write to.
func (msc *SCTPConn) ResetWriterStream() {
	msc.wmu.Lock()
	msc.writerStream = InvalidStreamID
	msc.wmu.Unlock()
}

// SetWriterStream resets current write stream so the next Write adaptor call
// will use either the current Write stream (if set), current Read stream (if set)
// or the protocol specific default stream.
func (msc *SCTPConn) SetWriterStream(stream uint) uint {
	msc.wmu.Lock()
	stream, msc.writerStream = msc.writerStream, stream
	msc.wmu.Unlock()
	return stream
}

// Read 'adaptor' reads data from the specified association while maintaining stream continuity.
// Read implements io.Reader interface on multi-stream protocols for stream unaware (legacy) applications.
// Read will guarantee that every read into a single buffer 'b' is sourced from a single stream and that
// multiple consecutive & concurrent reads will continue from the same stream between calls to ResetCurrentStream or
// SetCurrentStream.
// Calls to Read & ResetCurrentStream/SetCurrentStream should be synchronized
func (msc *SCTPConn) Read(b []byte) (n int, err error) {
	var strm uint
	msc.mu.RLock() // block changes to currStream during a single read

	for {
		if msc.currStream == InvalidStreamID { // first read after reset]
			n, strm, err = msc.ReadAny(b)
			if err == nil && msc.currStream != strm {
				msc.mu.RUnlock()
				msc.mu.Lock()
				if msc.currStream == InvalidStreamID { // msc.currStream may have changed, check again
					msc.currStream = strm
				} else if msc.currStream != strm {
					// Worst case scenario - concurrent read completed first and received from a different stream
					msc.bufferStreamData(b[0:n], strm)
					msc.mu.Unlock()
					msc.mu.RLock()
					continue
				}
				msc.mu.Unlock()
			} else {
				msc.mu.RUnlock()
			}
			return
		}
		// Stream # is already set, keep reading from it until next reset
		strm = msc.currStream
		n, err = msc.ReadStream(b, strm)
		msc.mu.RUnlock()
		return
	}
}

// Write writes data to the association while maintaining stream continuity.
// The write stream will be selected in the following order:
//  1. If current write stream is set (is not InvalidStreamID), it'll be used for writing.
//  2. If current read stream is set, it'll be used for writing.
//  3. If neither current write nor current read streams are set, write will use default
//     protocol stream (0 for the current SCTP implementation).
func (msc *SCTPConn) Write(b []byte) (int, error) {
	msc.wmu.RLock() // block changes to msc.writerStream during write
	defer msc.wmu.RUnlock()

	stream := msc.writerStream
	// If writer stream is set by a user, stick with it
	if stream == InvalidStreamID {
		stream = msc.CurrentStream()
	}
	info := &sctp.SndInfo{PPID: DiameterPPID}

	// If writer stream is not set, stick with the reader stream #
	if stream != InvalidStreamID {
		info.Stream = uint16(stream)
	}
	return msc.SendMsg(b, sctp.SendOptions{Info: info})
}

// Dial connects to the address on the named SCTP network.
func (d sctpDialer) Dial(network, address string) (net.Conn, error) {
	sctpAddr, err := sctp.ResolveAddr(network, address)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if d.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.Timeout)
		defer cancel()
	}
	conn, err := diameterSCTPConfig().Dial(ctx, network, d.LocalAddr, sctpAddr)
	if err != nil {
		return nil, err
	}
	return newSCTPConn(conn), nil
}

// Dial - SCTP dial for stream unaware apps.
func (d sctpSingleStreamDialer) Dial(network, address string) (net.Conn, error) {
	return sctpDialer(d).Dial(network, address)
}

// Accept implements the Accept method in the listener interface for sctpListener (see: MultistreamListen).
func (l sctpListener) Accept() (net.Conn, error) {
	conn, err := l.AcceptSCTP()
	if err != nil {
		return nil, err
	}
	return newSCTPConn(conn), nil
}
