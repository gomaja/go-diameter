package logtest

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type contextKey struct{}

type logValue string

func (v logValue) LogValue() slog.Value { return slog.GroupValue(slog.String("value", string(v))) }

func TestRecorderResolvesGroupsAndKeepsEveryRecord(t *testing.T) {
	r := New()
	ctx := context.WithValue(context.Background(), contextKey{}, "context")
	logger := r.Logger().With("root", "present").WithGroup("outer").With("before", logValue("resolved")).WithGroup("inner")
	const count = 2000
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			for n := i; n < count; n += 4 {
				logger.InfoContext(ctx, "record", slog.Int("index", n), slog.Any("after", logValue("also resolved")))
			}
		})
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	records, err := r.Wait(waitCtx, count)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != count {
		t.Fatalf("records=%d, want %d", len(records), count)
	}
	seen := make(map[int64]bool, count)
	for _, record := range records {
		for key, want := range map[string]string{"root": "present", "outer.before.value": "resolved", "outer.inner.after.value": "also resolved"} {
			if got := Attr(record, key).String(); got != want {
				t.Fatalf("%s=%q, want %q", key, got, want)
			}
		}
		n := Attr(record, "outer.inner.index").Int64()
		if seen[n] {
			t.Fatalf("duplicate index %d", n)
		}
		seen[n] = true
	}
	for _, got := range r.Contexts() {
		if got != ctx {
			t.Fatal("record context lost")
		}
	}
	records[0].AddAttrs(slog.String("mutated", "outside"))
	if HasAttr(r.Records()[0], "mutated") {
		t.Fatal("snapshot mutated stored record")
	}
}

type observedContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *observedContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

func TestRecorderWaitCanceled(t *testing.T) {
	r := New()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	observed := &observedContext{Context: ctx, checked: make(chan struct{})}
	go func() { _, err := r.Wait(observed, 1); done <- err }()
	<-observed.checked
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wait=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not wake waiter")
	}
}

func TestRecordsSnapshotDoesNotAliasGroups(t *testing.T) {
	r := New()
	r.Logger().WithGroup("outer").Info("record", slog.Group("inner", slog.String("value", "kept")))
	got := r.Records()
	group := Attr(got[0], "outer.inner").Group()
	group[0] = slog.String("value", "changed")
	if v := Attr(r.Records()[0], "outer.inner.value").String(); v != "kept" {
		t.Fatalf("snapshot changed stored value to %q", v)
	}
}

func TestWaitProgressRenewsIdleBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New()
		done := make(chan struct{})
		defer func() { <-done }()
		go func() {
			defer close(done)
			for range 4 {
				time.Sleep(750 * time.Millisecond)
				r.Logger().Info("progress")
			}
		}()
		records, err := r.WaitProgress(t.Context(), 4, time.Second)
		if err != nil || len(records) != 4 {
			t.Fatalf("progress records=%d error=%v", len(records), err)
		}
	})
}
func TestWaitProgressStopsOnStall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New()
		done := make(chan struct{})
		defer func() { <-done }()
		go func() { defer close(done); time.Sleep(750 * time.Millisecond); r.Logger().Info("one") }()
		start := time.Now()
		records, err := r.WaitProgress(t.Context(), 2, time.Second)
		if !errors.Is(err, context.DeadlineExceeded) || len(records) != 1 {
			t.Fatalf("stall records=%d error=%v", len(records), err)
		}
		if elapsed := time.Since(start); elapsed != 1750*time.Millisecond {
			t.Fatalf("idle expiry after %v, want 1.75s", elapsed)
		}
	})
}
func TestWaitProgressHonorsOverallDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := New()
		done := make(chan struct{})
		defer func() { <-done }()
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		go func() {
			defer close(done)
			for range 5 {
				time.Sleep(500 * time.Millisecond)
				r.Logger().Info("progress")
			}
		}()
		start := time.Now()
		_, err := r.WaitProgress(ctx, 10, time.Second)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != 2*time.Second {
			t.Fatalf("overall deadline error=%v elapsed=%v", err, time.Since(start))
		}
	})
}

func TestOperationDeadlineRenewsAndClips(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		start := time.Now()
		if got := Deadline(ctx, time.Second); !got.Equal(start.Add(time.Second)) {
			t.Fatalf("first deadline=%v", got)
		}
		time.Sleep(500 * time.Millisecond)
		if got := Deadline(ctx, time.Second); !got.Equal(start.Add(1500 * time.Millisecond)) {
			t.Fatalf("deadline did not renew: %v", got)
		}
		if got := Deadline(ctx, 3*time.Second); !got.Equal(start.Add(2 * time.Second)) {
			t.Fatalf("deadline exceeds context: %v", got)
		}
	})
}
