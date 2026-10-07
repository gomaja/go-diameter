//go:build linux && !386

package test

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/sm"
)

func TestAnswersAcceptPlainWriter(t *testing.T) {
	for _, name := range []string{"AIA", "ULA"} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("writer assertion panicked: %v", p)
				}
			}()
			var w bytes.Buffer
			m := diam.NewRequest(318, 16777251, nil).Answer(diam.Success)
			var n int64
			var err error
			if name == "AIA" {
				n, err = testSendAIA(&w, m, 1)
			} else {
				n, err = testSendULA(&sm.Settings{}, &w, m)
			}
			if err != nil || n != int64(w.Len()) || n == 0 {
				t.Fatalf("write = %d, %v (%d bytes)", n, err, w.Len())
			}
		})
	}
}
