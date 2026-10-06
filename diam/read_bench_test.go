package diam

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict"
)

func BenchmarkReadMessageParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		reader := bytes.NewReader(testMessage)
		for pb.Next() {
			if _, err := ReadMessage(reader, dict.Default); err != nil {
				b.Error(err)
				return
			}
			reader.Reset(testMessage)
		}
	})
}
