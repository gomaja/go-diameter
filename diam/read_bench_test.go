package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict/creditcontrol"
)

func BenchmarkReadMessageParallel(b *testing.B) {
	testDict := newTestDictionary(creditcontrol.Dictionary())

	b.RunParallel(func(pb *testing.PB) {
		reader := bytes.NewReader(testMessage)
		for pb.Next() {
			if _, err := ReadMessage(reader, testDict); err != nil {
				b.Error(err)
				return
			}
			reader.Reset(testMessage)
		}
	})
}
