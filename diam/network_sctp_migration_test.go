package diam

import (
	"io"
	"testing"

	"github.com/gomaja/go-sctp"
)

type scriptedSCTPReceiver struct {
	reads []struct {
		data string
		info sctp.MsgInfo
		err  error
	}
	index int
}

func (r *scriptedSCTPReceiver) RecvMsg(b []byte) (int, sctp.MsgInfo, error) {
	read := r.reads[r.index]
	r.index++
	return copy(b, read.data), read.info, read.err
}

func TestRecvSCTPDataSkipsNotifications(t *testing.T) {
	r := &scriptedSCTPReceiver{reads: []struct {
		data string
		info sctp.MsgInfo
		err  error
	}{
		{data: "notification", info: sctp.MsgInfo{Notification: true}},
		{data: "diameter", info: sctp.MsgInfo{Rcv: sctp.RcvInfo{Stream: 7}}},
	}}
	b := make([]byte, 64)
	n, info, err := recvSCTPData(r, b)
	if err != nil || string(b[:n]) != "diameter" || info.Rcv.Stream != 7 || r.index != 2 {
		t.Fatalf("read = %q, %+v, %v; consumed %d records", b[:n], info, err, r.index)
	}
}

func TestRecvSCTPDataReturnsReadError(t *testing.T) {
	r := &scriptedSCTPReceiver{reads: []struct {
		data string
		info sctp.MsgInfo
		err  error
	}{{err: io.EOF}}}
	_, _, err := recvSCTPData(r, make([]byte, 64))
	if err != io.EOF {
		t.Fatalf("read error = %v, want EOF", err)
	}
}
