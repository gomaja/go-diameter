package diam

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"

	"github.com/gomaja/go-sctp"
)

func restartNotification(state sctp.AssocChangeState, size int) []byte {
	b := make([]byte, size)
	binary.NativeEndian.PutUint16(b, uint16(sctp.EventAssocChange))
	binary.NativeEndian.PutUint32(b[4:], uint32(size))
	binary.NativeEndian.PutUint16(b[8:], uint16(state))
	binary.NativeEndian.PutUint16(b[12:], 7)
	binary.NativeEndian.PutUint16(b[14:], 9)
	binary.NativeEndian.PutUint32(b[16:], 123)
	return b
}

func TestSCTPRestartBeforeData(t *testing.T) {
	r := &scriptedSCTPReceiver{reads: []struct {
		data string
		info sctp.MsgInfo
		err  error
	}{
		{data: string(restartNotification(sctp.AssocRestart, 20)), info: sctp.MsgInfo{Notification: true, EOR: true}},
		{data: "new-generation", info: sctp.MsgInfo{EOR: true}},
	}}
	n, _, err := recvSCTPData(r, make([]byte, 64), true)
	if n != 0 || err == nil || r.index != 1 {
		t.Fatalf("restart read = %d, %v; consumed %d records, want zero-byte marker before DATA", n, err, r.index)
	}
}

type sctpRestartRead struct {
	data string
	info sctp.MsgInfo
	err  error
}

func restartReceiver(reads ...sctpRestartRead) *scriptedSCTPReceiver {
	r := &scriptedSCTPReceiver{}
	for _, v := range reads {
		r.reads = append(r.reads, struct {
			data string
			info sctp.MsgInfo
			err  error
		}{v.data, v.info, v.err})
	}
	return r
}

func notificationRead(b []byte, eor bool) sctpRestartRead {
	return sctpRestartRead{data: string(b), info: sctp.MsgInfo{Notification: true, EOR: eor}}
}

func TestSCTPRestartNotificationFragments(t *testing.T) {
	for split := 1; split < 20; split++ {
		t.Run(fmt.Sprint(split), func(t *testing.T) {
			event := restartNotification(sctp.AssocRestart, 20)
			r := restartReceiver(notificationRead(event[:split], false), notificationRead(event[split:], true), sctpRestartRead{data: "untouched"})
			n, _, err := recvSCTPData(r, make([]byte, 64), true)
			var restart *TransportRestartError
			if n != 0 || !errors.As(err, &restart) || restart.AssociationID != 123 || restart.InboundStreams != 9 || restart.OutboundStreams != 7 || r.index != 2 {
				t.Fatalf("read=%d, %v, marker=%+v, consumed=%d", n, err, restart, r.index)
			}
		})
	}
	event := restartNotification(sctp.AssocRestart, 20)
	r := restartReceiver()
	for _, v := range event {
		r.reads = append(r.reads, struct {
			data string
			info sctp.MsgInfo
			err  error
		}{data: string([]byte{v}), info: sctp.MsgInfo{Notification: true}})
	}
	r.reads[len(r.reads)-1].info.EOR = true
	_, _, err := recvSCTPData(r, make([]byte, 1), true)
	var restart *TransportRestartError
	if !errors.As(err, &restart) || r.index != 20 {
		t.Fatalf("one-byte read: %v, consumed=%d", err, r.index)
	}
}

func TestSCTPRestartMalformedNotifications(t *testing.T) {
	oversized := restartNotification(sctp.AssocRestart, 20)
	binary.NativeEndian.PutUint32(oversized[4:], sctp.NotificationReassemblyLimit+1)
	shortDeclared := restartNotification(sctp.AssocRestart, 20)
	binary.NativeEndian.PutUint32(shortDeclared[4:], 7)
	longerDeclared := restartNotification(sctp.AssocRestart, 20)
	binary.NativeEndian.PutUint32(longerDeclared[4:], 21)
	shorterDeclared := restartNotification(sctp.AssocRestart, 20)
	binary.NativeEndian.PutUint32(shorterDeclared[4:], 19)
	cases := []struct {
		name  string
		reads []sctpRestartRead
		want  error
	}{
		{"short-header", []sctpRestartRead{notificationRead([]byte{1, 2, 3}, true)}, sctp.ErrShortNotification},
		{"short-association", []sctpRestartRead{notificationRead(restartNotification(sctp.AssocRestart, 20)[:19], true)}, sctp.ErrShortNotification},
		{"declared-oversize", []sctpRestartRead{notificationRead(oversized, false)}, sctp.ErrNotificationTooLong},
		{"invalid-length", []sctpRestartRead{notificationRead(shortDeclared, true)}, sctp.ErrShortNotification},
		{"truncated", []sctpRestartRead{notificationRead(longerDeclared, true)}, sctp.ErrShortNotification},
		{"trailing-bytes", []sctpRestartRead{notificationRead(shorterDeclared, true)}, sctp.ErrShortNotification},
		{"zero-progress", []sctpRestartRead{notificationRead(nil, false)}, sctp.ErrShortNotification},
		{"data-interrupted", []sctpRestartRead{notificationRead([]byte{1}, false), {data: "data"}}, sctp.ErrShortNotification},
		{"EOF-interrupted", []sctpRestartRead{notificationRead([]byte{1}, false), {err: io.EOF}}, io.EOF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := restartReceiver(append(c.reads, sctpRestartRead{err: io.EOF})...)
			n, _, err := recvSCTPData(r, make([]byte, 64), true)
			var restart *TransportRestartError
			if n != 0 || !errors.Is(err, c.want) || errors.As(err, &restart) {
				t.Fatalf("read=%d,%v; want terminal %v", n, err, c.want)
			}
		})
	}
}

func TestSCTPRestartNotificationLimit(t *testing.T) {
	for _, size := range []int{sctp.NotificationReassemblyLimit - 1, sctp.NotificationReassemblyLimit} {
		event := restartNotification(sctp.AssocRestart, size)
		r := restartReceiver(notificationRead(event[:size-1], false), notificationRead(event[size-1:], true))
		_, _, err := recvSCTPData(r, make([]byte, size), true)
		var restart *TransportRestartError
		if !errors.As(err, &restart) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
	event := restartNotification(sctp.AssocRestart, sctp.NotificationReassemblyLimit)
	r := restartReceiver(notificationRead(event, false), notificationRead([]byte{0}, true))
	_, _, err := recvSCTPData(r, make([]byte, len(event)), true)
	if !errors.Is(err, sctp.ErrNotificationTooLong) {
		t.Fatalf("actual oversize: %v", err)
	}
}

func TestSCTPRestartUnrelatedNotifications(t *testing.T) {
	unknown := make([]byte, 8)
	binary.NativeEndian.PutUint16(unknown, 0xfffe)
	binary.NativeEndian.PutUint32(unknown[4:], 8)
	for _, state := range []sctp.AssocChangeState{sctp.AssocCommUp, sctp.AssocCommLost, sctp.AssocShutdownComplete, sctp.AssocCantStart} {
		r := restartReceiver(notificationRead(restartNotification(state, 20), true), notificationRead(unknown, true), sctpRestartRead{data: "data", info: sctp.MsgInfo{Rcv: sctp.RcvInfo{Stream: 7}}})
		b := make([]byte, 64)
		n, info, err := recvSCTPData(r, b, true)
		if err != nil || string(b[:n]) != "data" || info.Rcv.Stream != 7 || r.index != 3 {
			t.Fatalf("state %v: %q,%+v,%v consumed%d", state, b[:n], info, err, r.index)
		}
	}
}

func TestSCTPRestartDialedNotificationsUnchanged(t *testing.T) {
	r := restartReceiver(notificationRead(restartNotification(sctp.AssocRestart, 20), true), sctpRestartRead{data: "dialed"})
	msc := newSCTPConn(nil)
	msc.receiver = r
	b := make([]byte, 64)
	n, _, err := msc.ReadAny(b)
	if err != nil || string(b[:n]) != "dialed" || r.index != 2 {
		t.Fatalf("dialed read %q,%v consumed%d", b[:n], err, r.index)
	}
	if len(diameterSCTPConfig().Notifications) != 0 {
		t.Fatal("dial config subscribes notifications")
	}
	if !reflect.DeepEqual(diameterSCTPListenConfig().Notifications, []sctp.EventType{sctp.EventAssocChange}) {
		t.Fatal("listen config omits association subscription")
	}
}

func TestSCTPRestartMarkerAndReset(t *testing.T) {
	r := restartReceiver(
		sctpRestartRead{data: "old-other-stream", info: sctp.MsgInfo{Rcv: sctp.RcvInfo{Stream: 9}}},
		notificationRead(restartNotification(sctp.AssocRestart, 20), true),
		sctpRestartRead{data: "new", info: sctp.MsgInfo{Rcv: sctp.RcvInfo{Stream: 3}}},
	)
	msc := newRestartSCTPConn(nil)
	msc.receiver = r
	msc.SetCurrentStream(7)
	msc.SetWriterStream(7)
	b := make([]byte, 64)
	n, err := msc.Read(b)
	var restart *TransportRestartError
	if n != 0 || !errors.As(err, &restart) || r.index != 2 {
		t.Fatalf("Read=%d,%v consumed%d", n, err, r.index)
	}
	if msc.s.streamMap[9].Len() == 0 {
		t.Fatal("test did not buffer old data")
	}
	if n, _, err := msc.ReadAny(b); n != 0 || !errors.As(err, &restart) || r.index != 2 {
		t.Fatalf("latched ReadAny=%d,%v consumed%d", n, err, r.index)
	}
	if n, err := msc.ReadStream(b, 9); n != 0 || !errors.As(err, &restart) || r.index != 2 {
		t.Fatalf("latched ReadStream=%d,%v consumed%d", n, err, r.index)
	}
	done := make(chan struct{})
	go func() { msc.ResetForRestart(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reset deadlocked after outer Read")
	}
	if msc.s.Len() != 0 || len(msc.s.streamMap) != 0 || msc.CurrentStream() != InvalidStreamID || msc.CurrentWriterStream() != InvalidStreamID {
		t.Fatal("reset retained stream state")
	}
	n, err = msc.Read(b)
	if err != nil || string(b[:n]) != "new" || msc.CurrentStream() != 3 || r.index != 3 {
		t.Fatalf("renewed Read=%q,%v stream%d consumed%d", b[:n], err, msc.CurrentStream(), r.index)
	}
}

func TestSCTPRestartReadAtLeastPreservesPartialMarker(t *testing.T) {
	r := restartReceiver(sctpRestartRead{data: "old", info: sctp.MsgInfo{Rcv: sctp.RcvInfo{Stream: 7}}}, notificationRead(restartNotification(sctp.AssocRestart, 20), true), sctpRestartRead{data: "untouched"})
	msc := newRestartSCTPConn(nil)
	msc.receiver = r
	n, stream, err := msc.ReadAtLeast(make([]byte, 64), 20, InvalidStreamID)
	var restart *TransportRestartError
	if n != 3 || stream != 7 || !errors.As(err, &restart) || r.index != 2 {
		t.Fatalf("partial read %d stream%d err%v consumed%d", n, stream, err, r.index)
	}
}

func TestSCTPRestartSkipsTerminalErrorHandler(t *testing.T) {
	for _, handlerMarker := range []bool{false, true} {
		t.Run(fmt.Sprint(handlerMarker), func(t *testing.T) {
			read := notificationRead(restartNotification(sctp.AssocRestart, 20), true)
			if handlerMarker {
				read = sctpRestartRead{err: fmt.Errorf("callback: %w", &TransportRestartError{AssociationID: 123})}
			}
			r := restartReceiver(read)
			msc := newRestartSCTPConn(nil)
			msc.receiver = r
			calls := 0
			msc.SetErrorHandler(func(MultistreamConn, error) { calls++ })
			n, _, err := msc.ReadAny(make([]byte, 64))
			var restart *TransportRestartError
			if n != 0 || !errors.As(err, &restart) || calls != 0 {
				t.Fatalf("read%d,%v handler calls%d", n, err, calls)
			}
		})
	}
	msc := newRestartSCTPConn(nil)
	msc.receiver = restartReceiver(sctpRestartRead{err: io.EOF})
	calls := 0
	msc.SetErrorHandler(func(MultistreamConn, error) { calls++ })
	_, _, err := msc.ReadAny(make([]byte, 64))
	if err != io.EOF || calls != 1 {
		t.Fatalf("terminal read %v handler calls%d", err, calls)
	}
}

func FuzzSCTPRestartNotification(f *testing.F) {
	f.Add(restartNotification(sctp.AssocRestart, 20), uint8(10))
	f.Add([]byte{1, 2, 3}, uint8(1))
	f.Fuzz(func(t *testing.T, b []byte, split uint8) {
		if len(b) > sctp.NotificationReassemblyLimit+1 {
			return
		}
		cut := int(split)
		if cut > len(b) {
			cut = len(b)
		}
		reads := []sctpRestartRead{notificationRead(b, true)}
		if cut > 0 && cut < len(b) {
			reads = []sctpRestartRead{notificationRead(b[:cut], false), notificationRead(b[cut:], true)}
		}
		reads = append(reads, sctpRestartRead{err: io.EOF})
		r := restartReceiver(reads...)
		n, _, err := recvSCTPData(r, make([]byte, len(b)+1), true)
		if n != 0 {
			t.Fatalf("notification leaked %d data bytes", n)
		}
		var restart *TransportRestartError
		if errors.As(err, &restart) {
			event, parseErr := sctp.ParseNotification(b)
			change, ok := event.(*sctp.AssocChange)
			if parseErr != nil || !ok || change.State != sctp.AssocRestart || restart.AssociationID != uint32(change.AssocID) || restart.InboundStreams != change.InStreams || restart.OutboundStreams != change.OutStreams {
				t.Fatalf("invalid restart marker %+v for %x", restart, b)
			}
		}
	})
}

func TestSCTPRestartBufferedDataCannotMaskMarker(t *testing.T) {
	msc := newRestartSCTPConn(nil)
	msc.bufferStreamData([]byte("retired"), 0)
	marker := &TransportRestartError{AssociationID: 123}
	n, err := msc.verifyStreamBuff(make([]byte, 64), 0, 0, marker)
	var restart *TransportRestartError
	if n != 0 || !errors.As(err, &restart) {
		t.Fatalf("buffer masked marker: %d,%v", n, err)
	}
}

func TestSCTPRestartInterruptsDiameterMessage(t *testing.T) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	for _, body := range []bool{false, true} {
		t.Run(fmt.Sprintf("body=%v", body), func(t *testing.T) {
			data := func(b []byte, stream uint16) sctpRestartRead {
				return sctpRestartRead{data: string(b), info: sctp.MsgInfo{Rcv: sctp.RcvInfo{Stream: stream}}}
			}
			reads := []sctpRestartRead{data(testMessage[:7], 7)}
			if body {
				reads = []sctpRestartRead{data(testMessage[:HeaderLength], 7), data(testMessage[HeaderLength:HeaderLength+7], 7)}
			}
			event := restartNotification(sctp.AssocRestart, 20)
			reads = append(reads, data([]byte("stale"), 9), notificationRead(event[:10], false), notificationRead(event[10:], true),
				data(testMessage[:HeaderLength], 3), data(testMessage[HeaderLength:], 3))
			r := restartReceiver(reads...)
			msc := newRestartSCTPConn(nil)
			msc.receiver = r
			msc.SetWriterStream(7)
			_, err := ReadMessage(msc, testDict)
			var restart *TransportRestartError
			if !errors.As(err, &restart) || r.index != len(reads)-2 {
				t.Fatalf("interrupted message error=%v consumed=%d", err, r.index)
			}
			msc.ResetForRestart()
			if len(msc.s.streamMap) != 0 || msc.CurrentStream() != InvalidStreamID || msc.CurrentWriterStream() != InvalidStreamID {
				t.Fatal("reset retained retired message state")
			}
			m, err := ReadMessage(msc, testDict)
			if err != nil || m.MessageStream() != 3 || r.index != len(reads) {
				t.Fatalf("fresh message=%v error=%v consumed=%d", m, err, r.index)
			}
			wire, err := m.Serialize()
			if err != nil || !reflect.DeepEqual(wire, testMessage) {
				t.Fatalf("fresh message changed: %v", err)
			}
		})
	}
}
