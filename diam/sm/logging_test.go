package sm

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

func waitLog(t *testing.T, recorder *logtest.Recorder, n int) slog.Record {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	records, err := recorder.Wait(ctx, n)
	if err != nil {
		t.Fatalf("waiting for %d records: %v; have %v", n, err, records)
	}
	return records[n-1]
}
func logError(record slog.Record) error {
	err, _ := logtest.Attr(record, "error").Any().(error)
	return err
}
