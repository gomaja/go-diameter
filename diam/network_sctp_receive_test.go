package diam

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/gomaja/go-sctp"
)

func TestRecvSCTPDataReadResults(t *testing.T) {
	info := sctp.MsgInfo{EOR: true, Rcv: sctp.RcvInfo{Stream: 7, PPID: DiameterPPID}, HasNxt: true, Nxt: sctp.NxtInfo{Stream: 9}}
	for _, aware := range []bool{false, true} {
		for _, tc := range []struct {
			name string
			read sctpRestartRead
		}{
			{"data", sctpRestartRead{data: "data", info: info}},
			{"data-with-EOF", sctpRestartRead{data: "data", info: info, err: io.EOF}},
			{"EOF", sctpRestartRead{err: io.EOF}},
			{"closed", sctpRestartRead{err: net.ErrClosed}},
			{"deadline", sctpRestartRead{err: os.ErrDeadlineExceeded}},
			{"short-notification", sctpRestartRead{err: &net.OpError{Op: "read", Net: "sctp", Err: sctp.ErrShortNotification}}},
			{"oversized-notification", sctpRestartRead{err: &net.OpError{Op: "read", Net: "sctp", Err: sctp.ErrNotificationTooLong}}},
		} {
			t.Run(fmt.Sprintf("%s/restart=%v", tc.name, aware), func(t *testing.T) {
				r := restartReceiver(tc.read, sctpRestartRead{data: "untouched"})
				b := make([]byte, 64)
				n, gotInfo, err := recvSCTPData(r, b, aware)
				if string(b[:n]) != tc.read.data || gotInfo != tc.read.info || err != tc.read.err || r.index != 1 {
					t.Fatalf("read = %q, %+v, %T(%v); consumed %d; want %+v", b[:n], gotInfo, err, err, r.index, tc.read)
				}
			})
		}
	}
}

func TestRecvSCTPDataEmptyBuffer(t *testing.T) {
	for _, aware := range []bool{false, true} {
		for _, b := range [][]byte{nil, {}} {
			r := restartReceiver()
			n, info, err := recvSCTPData(r, b, aware)
			if n != 0 || info != (sctp.MsgInfo{}) || err != nil || r.index != 0 {
				t.Fatalf("empty buffer/restart=%v: %d, %+v, %v; consumed %d", aware, n, info, err, r.index)
			}
		}
	}
}

type sctpCountReceiver struct {
	n, calls int
}

func (r *sctpCountReceiver) RecvMsg([]byte) (int, sctp.MsgInfo, error) {
	r.calls++
	if r.calls > 1 {
		return 0, sctp.MsgInfo{}, io.EOF
	}
	return r.n, sctp.MsgInfo{Notification: true, EOR: true}, nil
}

func TestRecvSCTPDataNotificationReadCount(t *testing.T) {
	for _, count := range []int{-1, 0, 9} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("read count %d panicked: %v", count, p)
				}
			}()
			r := &sctpCountReceiver{n: count}
			n, info, err := recvSCTPData(r, make([]byte, 8), true)
			if n != 0 || info != (sctp.MsgInfo{}) || err != sctp.ErrShortNotification || r.calls != 1 {
				t.Fatalf("read count %d = %d, %+v, %v; calls=%d", count, n, info, err, r.calls)
			}
		})
	}
}

func TestRecvSCTPDataHandlerRestart(t *testing.T) {
	for _, aware := range []bool{false, true} {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("restart=%v/wrapped=%v", aware, wrapped), func(t *testing.T) {
				marker := &TransportRestartError{AssociationID: 123, InboundStreams: 9, OutboundStreams: 7}
				var want error = marker
				if wrapped {
					want = &net.OpError{Op: "read", Net: "sctp", Err: marker}
				}
				r := restartReceiver(sctpRestartRead{err: want}, sctpRestartRead{data: "fresh"})
				b := make([]byte, 64)
				n, info, err := recvSCTPData(r, b, aware)
				var got *TransportRestartError
				if n != 0 || info != (sctp.MsgInfo{}) || err != want || !errors.As(err, &got) || got != marker || r.index != 1 {
					t.Fatalf("handler restart = %d, %+v, %v; marker=%+v; consumed %d", n, info, err, got, r.index)
				}
				if n, _, err = recvSCTPData(r, b, aware); err != nil || string(b[:n]) != "fresh" || r.index != 2 {
					t.Fatalf("following DATA = %q, %v; consumed %d", b[:n], err, r.index)
				}
			})
		}
	}
}

func TestRecvSCTPDataNotificationRecords(t *testing.T) {
	for _, size := range []int{1, 7, HeaderLength, 64, sctp.NotificationMaxSize} {
		for _, aware := range []bool{false, true} {
			t.Run(fmt.Sprintf("buffer=%d/restart=%v", size, aware), func(t *testing.T) {
				r := restartReceiver()
				unknown := make([]byte, 8)
				binary.NativeEndian.PutUint16(unknown, 0xfffe)
				binary.NativeEndian.PutUint32(unknown[4:], uint32(len(unknown)))
				for _, note := range [][]byte{restartNotification(sctp.AssocCommUp, 2049), unknown} {
					for start := 0; start < len(note); start += size {
						end := min(start+size, len(note))
						r.reads = append(r.reads, restartReceiver(notificationRead(note[start:end], end == len(note))).reads...)
					}
				}
				wantInfo := sctp.MsgInfo{EOR: true, Rcv: sctp.RcvInfo{Stream: 5, PPID: DiameterPPID}}
				r.reads = append(r.reads, restartReceiver(sctpRestartRead{data: "D", info: wantInfo}).reads...)
				b := make([]byte, size)
				n, info, err := recvSCTPData(r, b, aware)
				if err != nil || string(b[:n]) != "D" || info != wantInfo || r.index != len(r.reads) {
					t.Fatalf("following DATA = %q, %+v, %v; consumed %d/%d", b[:n], info, err, r.index, len(r.reads))
				}
			})
		}
	}
}

func TestRecvSCTPDataInterruptedNotification(t *testing.T) {
	for _, cause := range []error{io.EOF, net.ErrClosed, os.ErrDeadlineExceeded, &net.OpError{Op: "read", Net: "sctp", Err: sctp.ErrShortNotification}, &net.OpError{Op: "read", Net: "sctp", Err: sctp.ErrNotificationTooLong}} {
		t.Run(cause.Error(), func(t *testing.T) {
			r := restartReceiver(notificationRead([]byte{1}, false), sctpRestartRead{err: cause}, sctpRestartRead{data: "untouched"})
			n, info, err := recvSCTPData(r, make([]byte, 64), true)
			if n != 0 || info != (sctp.MsgInfo{}) || errors.Unwrap(err) != cause || err.Error() != "diam: incomplete SCTP notification: "+cause.Error() || r.index != 2 {
				t.Fatalf("interruption = %d, %+v, %v; consumed %d", n, info, err, r.index)
			}
		})
	}
	marker := &net.OpError{Op: "read", Net: "sctp", Err: &TransportRestartError{AssociationID: 123}}
	r := restartReceiver(notificationRead([]byte{1}, false), sctpRestartRead{err: marker}, sctpRestartRead{data: "untouched"})
	if n, info, err := recvSCTPData(r, make([]byte, 64), true); n != 0 || info != (sctp.MsgInfo{}) || err != marker || r.index != 2 {
		t.Fatalf("restart during notification = %d, %+v, %v; consumed %d", n, info, err, r.index)
	}
}

func TestRecvSCTPDataNotificationDecodeErrors(t *testing.T) {
	badLength := restartNotification(sctp.AssocRestart, 20)
	binary.NativeEndian.PutUint32(badLength[4:], 7)
	oversized := restartNotification(sctp.AssocRestart, 20)
	binary.NativeEndian.PutUint32(oversized[4:], sctp.NotificationReassemblyLimit+1)
	shortExtent := restartNotification(sctp.AssocRestart, 20)
	binary.NativeEndian.PutUint32(shortExtent[4:], 19)
	badAddress := make([]byte, 148)
	binary.NativeEndian.PutUint16(badAddress, uint16(sctp.EventPeerAddrChange))
	binary.NativeEndian.PutUint32(badAddress[4:], uint32(len(badAddress)))
	for _, tc := range []struct {
		name string
		note []byte
		want error
	}{
		{"short-header", []byte{1, 2, 3}, sctp.ErrShortNotification},
		{"truncated", restartNotification(sctp.AssocRestart, 20)[:19], sctp.ErrShortNotification},
		{"invalid-declaration", badLength, sctp.ErrShortNotification},
		{"oversized-declaration", oversized, sctp.ErrNotificationTooLong},
		{"short-association-extent", shortExtent, sctp.ErrShortNotification},
		{"malformed-address", badAddress, syscall.EINVAL},
	} {
		for _, split := range []int{len(tc.note), 1} {
			t.Run(fmt.Sprintf("%s/piece=%d", tc.name, split), func(t *testing.T) {
				r := restartReceiver()
				for start := 0; start < len(tc.note); start += split {
					end := min(start+split, len(tc.note))
					r.reads = append(r.reads, restartReceiver(notificationRead(tc.note[start:end], end == len(tc.note))).reads...)
				}
				pieces := len(r.reads)
				r.reads = append(r.reads, restartReceiver(sctpRestartRead{data: "untouched"}).reads...)
				n, info, err := recvSCTPData(r, make([]byte, len(tc.note)), true)
				_, parseErr := sctp.ParseNotification(tc.note)
				if n != 0 || info != (sctp.MsgInfo{}) || !errors.Is(err, tc.want) || errors.Unwrap(err) == nil || err.Error() != "diam: parse SCTP notification: "+parseErr.Error() || r.index != pieces {
					t.Fatalf("decode = %d, %+v, %v; consumed %d/%d", n, info, err, r.index, pieces)
				}
			})
		}
	}
}

func TestRecvSCTPDataNotificationExtent(t *testing.T) {
	for _, size := range []int{21, sctp.NotificationReassemblyLimit + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			note := append(restartNotification(sctp.AssocRestart, 20), make([]byte, size-20)...)
			r := restartReceiver(notificationRead(note, true), sctpRestartRead{data: "untouched"})
			n, info, err := recvSCTPData(r, make([]byte, size), true)
			marker, ok := err.(*TransportRestartError)
			if n != 0 || info != (sctp.MsgInfo{}) || !ok || marker.AssociationID != 123 || marker.InboundStreams != 9 || marker.OutboundStreams != 7 || r.index != 1 {
				t.Fatalf("notification extent = %d, %+v, %v; marker=%+v; consumed %d", n, info, err, marker, r.index)
			}
		})
	}
}

func TestRecvSCTPDataNotificationNeedsRecordEnd(t *testing.T) {
	invalid := restartNotification(sctp.AssocRestart, 20)
	binary.NativeEndian.PutUint32(invalid[4:], 7)
	oversized := restartNotification(sctp.AssocRestart, 20)
	binary.NativeEndian.PutUint32(oversized[4:], sctp.NotificationReassemblyLimit+1)
	for _, tc := range []struct {
		name string
		note []byte
	}{
		{"invalid-declaration", invalid},
		{"oversized-declaration", oversized},
		{"extra-bytes", append(restartNotification(sctp.AssocRestart, 20), 0)},
		{"oversized-record", append(restartNotification(sctp.AssocRestart, sctp.NotificationReassemblyLimit), 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := restartReceiver(notificationRead(tc.note, false), sctpRestartRead{err: io.EOF}, sctpRestartRead{data: "untouched"})
			n, info, err := recvSCTPData(r, make([]byte, len(tc.note)), true)
			if n != 0 || info != (sctp.MsgInfo{}) || errors.Unwrap(err) != io.EOF || err.Error() != "diam: incomplete SCTP notification: EOF" || r.index != 2 {
				t.Fatalf("incomplete record = %d, %+v, %v; consumed %d", n, info, err, r.index)
			}
		})
	}
}
