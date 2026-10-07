package diam

import (
	"bytes"
	"io"
	"testing"
)

type streamTestWriter struct {
	bytes.Buffer
	streams     []uint
	plainWrites int
	retry       bool
}

func (w *streamTestWriter) Write(p []byte) (int, error) { w.plainWrites++; return w.Buffer.Write(p) }
func (w *streamTestWriter) WriteStream(p []byte, stream uint) (int, error) {
	w.streams = append(w.streams, stream)
	if w.retry {
		w.retry = false
		n, _ := w.Buffer.Write(p[:3])
		return n, timeoutError{}
	}
	return w.Buffer.Write(p)
}
func (*streamTestWriter) CurrentWriterStream() uint { return 0 }
func (*streamTestWriter) ResetWriterStream()        {}
func (*streamTestWriter) SetWriterStream(uint) uint { return 0 }

type streamTestConn struct {
	Conn
	*streamTestWriter
}

func (c streamTestConn) Write(p []byte) (int, error) { return c.streamTestWriter.Write(p) }
func (c streamTestConn) WriteStream(p []byte, s uint) (int, error) {
	return c.streamTestWriter.WriteStream(p, s)
}

func TestMessageStreamThroughConnWrappers(t *testing.T) {
	for _, name := range []string{"writer", "direct", "one", "two", "opaque", "plain"} {
		for _, retry := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "", true: "/retry"}[retry], func(t *testing.T) {
				m, err := ReadMessage(bytes.NewReader(testMessage), nil)
				if err != nil {
					t.Fatal(err)
				}
				sink := &streamTestWriter{retry: retry}
				var c Conn = streamTestConn{streamTestWriter: sink}
				var w io.Writer = c
				switch name {
				case "writer":
					w = sink
				case "one":
					w = unwrapConn{c}
				case "two":
					w = unwrapConn{unwrapConn{c}}
				case "opaque":
					w = opaqueConn{c}
				case "plain":
					w = struct{ io.Writer }{sink}
				}
				n, err := m.WriteToStreamWithRetry(w, 7, 1)
				if err != nil || n != len(testMessage) || !bytes.Equal(sink.Bytes(), testMessage) {
					t.Fatalf("write = %d, %v; payload equal = %v", n, err, bytes.Equal(sink.Bytes(), testMessage))
				}
				want := 1
				if retry {
					want = 2
				}
				// Every Conn, opaque or not, is written with its WriteStream;
				// only a writer that is not a Conn gets a plain Write.
				plain := 0
				if name == "plain" {
					want = 0
					plain = 1
				}
				if len(sink.streams) != want || sink.plainWrites != plain {
					t.Fatalf("stream calls %v, plain writes %d; want %d/%d", sink.streams, sink.plainWrites, want, plain)
				}
				for _, stream := range sink.streams {
					if stream != 7 {
						t.Fatalf("stream = %d, want 7", stream)
					}
				}
			})
		}
	}
}

func TestResponseResetWriterStream(t *testing.T) {
	// Exercise SCTP's real bookkeeping without allocating an association.
	transport := &SCTPConn{currStream: 3, writerStream: InvalidStreamID}
	response := (&Server{}).newConn(transport).writer
	if old := response.SetWriterStream(7); old != InvalidStreamID {
		t.Fatalf("old stream = %d", old)
	}
	response.ResetWriterStream()
	if got := response.CurrentWriterStream(); got != InvalidStreamID {
		t.Fatalf("writer stream = %d, want InvalidStreamID", got)
	}
	if got := transport.CurrentStream(); got != 3 {
		t.Fatalf("reset changed read stream to %d", got)
	}
	response.ResetWriterStream()
	if got := response.CurrentWriterStream(); got != InvalidStreamID {
		t.Fatalf("second reset = %d", got)
	}
}

type streamInterceptConn struct {
	streamTestConn
	inner Conn
}

func (c streamInterceptConn) Unwrap() Conn { return c.inner }

func TestMessageStreamWrapperIntercepts(t *testing.T) {
	inner := &streamTestWriter{}
	outer := &streamTestWriter{}
	c := streamInterceptConn{streamTestConn{streamTestWriter: outer}, streamTestConn{streamTestWriter: inner}}
	m, err := ReadMessage(bytes.NewReader(testMessage), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.WriteToStream(c, 7); err != nil {
		t.Fatal(err)
	}
	if len(outer.streams) != 1 || outer.streams[0] != 7 || inner.Len() != 0 {
		t.Fatalf("outer streams %v, inner bytes %d", outer.streams, inner.Len())
	}
}

// countingConn is middleware that counts what it writes and forwards to the
// Conn it wraps, as a metrics wrapper would.
type countingConn struct {
	Conn
	writes, streamWrites int
}

func (c *countingConn) Unwrap() Conn { return c.Conn }
func (c *countingConn) Write(p []byte) (int, error) {
	c.writes++
	return c.Conn.Write(p)
}
func (c *countingConn) WriteStream(p []byte, s uint) (int, error) {
	c.streamWrites++
	return c.Conn.WriteStream(p, s)
}

// TestMessageStreamKeepsMiddlewareInPath checks that writing a message to a
// wrapper that has Unwrap still goes through the wrapper's own WriteStream,
// with the requested stream, instead of bypassing it to the inner Conn.
func TestMessageStreamKeepsMiddlewareInPath(t *testing.T) {
	sink := &streamTestWriter{}
	c := &countingConn{Conn: streamTestConn{streamTestWriter: sink}}
	m, err := ReadMessage(bytes.NewReader(testMessage), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.WriteToStream(c, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := m.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	if c.streamWrites != 2 || c.writes != 0 {
		t.Fatalf("wrapper saw %d stream writes and %d writes; want 2 and 0", c.streamWrites, c.writes)
	}
	if len(sink.streams) != 2 || sink.streams[0] != 7 {
		t.Fatalf("inner streams = %v; want [7 ...]", sink.streams)
	}
}
