// Package logtest records synchronous log output for library tests.
package logtest

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

type state struct {
	mu         sync.Mutex
	cond       *sync.Cond
	records    []slog.Record
	contexts   []context.Context
	lastRecord time.Time
}

// Recorder is a slog.Handler that retains every record, including resolved
// attributes attached through WithAttrs and WithGroup. All derived handlers
// share one record store.
type Recorder struct {
	state  *state
	attrs  []slog.Attr
	groups []string
}

// New creates an empty recorder. Every log level is enabled.
func New() *Recorder {
	s := &state{}
	s.cond = sync.NewCond(&s.mu)
	return &Recorder{state: s}
}

func (r *Recorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *Recorder) Logger() *slog.Logger                     { return slog.New(r) }

func resolve(a slog.Attr) slog.Attr {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		resolved := make([]slog.Attr, len(attrs))
		for i, child := range attrs {
			resolved[i] = resolve(child)
		}
		a.Value = slog.GroupValue(resolved...)
	}
	return a
}

func grouped(attrs []slog.Attr, groups []string) []slog.Attr {
	for i := len(groups) - 1; i >= 0; i-- {
		attrs = []slog.Attr{{Key: groups[i], Value: slog.GroupValue(attrs...)}}
	}
	return attrs
}

func (r *Recorder) Handle(ctx context.Context, record slog.Record) error {
	stored := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	stored.AddAttrs(r.attrs...)
	var attrs []slog.Attr
	record.Attrs(func(a slog.Attr) bool { attrs = append(attrs, resolve(a)); return true })
	stored.AddAttrs(grouped(attrs, r.groups)...)
	r.state.mu.Lock()
	r.state.records = append(r.state.records, stored)
	r.state.lastRecord = time.Now()
	r.state.contexts = append(r.state.contexts, ctx)
	r.state.cond.Broadcast()
	r.state.mu.Unlock()
	return nil
}

func (r *Recorder) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *r
	resolved := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		resolved[i] = resolve(a)
	}
	clone.attrs = append(append([]slog.Attr(nil), r.attrs...), grouped(resolved, r.groups)...)
	return &clone
}
func (r *Recorder) WithGroup(name string) slog.Handler {
	if name == "" {
		return r
	}
	clone := *r
	clone.groups = append(append([]string(nil), r.groups...), name)
	return &clone
}

func cloneRecords(records []slog.Record) []slog.Record {
	result := make([]slog.Record, len(records))
	for i, r := range records {
		copy := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
		r.Attrs(func(a slog.Attr) bool { copy.AddAttrs(resolve(a)); return true })
		result[i] = copy
	}
	return result
}

// Records returns a snapshot; callers cannot modify retained records.
func (r *Recorder) Records() []slog.Record {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	return cloneRecords(r.state.records)
}

// Contexts returns the contexts supplied to Handle, in record order.
func (r *Recorder) Contexts() []context.Context {
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	return append([]context.Context(nil), r.state.contexts...)
}

// Wait waits until at least n records exist or ctx ends. No polling or channel
// capacity can discard a record or a wake-up.
func (r *Recorder) Wait(ctx context.Context, n int) ([]slog.Record, error) {
	stop := context.AfterFunc(ctx, func() {
		r.state.mu.Lock()
		r.state.cond.Broadcast()
		r.state.mu.Unlock()
	})
	defer stop()
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	for len(r.state.records) < n && ctx.Err() == nil {
		r.state.cond.Wait()
	}
	records := cloneRecords(r.state.records)
	if len(records) >= n {
		return records, nil
	}
	return records, ctx.Err()
}

// Attr finds a record attribute, accepting dotted paths into groups.
func Attr(record slog.Record, key string) slog.Value {
	var found slog.Value
	var visit func(slog.Attr, string)
	visit = func(a slog.Attr, prefix string) {
		path := prefix + a.Key
		if path == key {
			found = a.Value
		}
		if a.Value.Kind() == slog.KindGroup {
			if a.Key != "" {
				path += "."
			}
			for _, child := range a.Value.Group() {
				visit(child, path)
			}
		}
	}
	record.Attrs(func(a slog.Attr) bool { visit(a, ""); return true })
	return found
}

// HasAttr reports whether an attribute exists, including attributes whose value
// is nil. Use Attr to retrieve its value.
func HasAttr(record slog.Record, key string) bool {
	var found bool
	var visit func(slog.Attr, string)
	visit = func(a slog.Attr, prefix string) {
		path := prefix + a.Key
		if path == key {
			found = true
		}
		if a.Value.Kind() == slog.KindGroup {
			prefix = path
			if !strings.HasSuffix(prefix, ".") && prefix != "" {
				prefix += "."
			}
			for _, child := range a.Value.Group() {
				visit(child, prefix)
			}
		}
	}
	record.Attrs(func(a slog.Attr) bool { visit(a, ""); return true })
	return found
}

// WaitProgress waits for n records, allowing idle between successive records.
// The caller's context bounds the complete operation.
func (r *Recorder) WaitProgress(ctx context.Context, n int, idle time.Duration) ([]slog.Record, error) {
	wake := func() {
		r.state.mu.Lock()
		r.state.cond.Broadcast()
		r.state.mu.Unlock()
	}
	stop := context.AfterFunc(ctx, wake)
	defer stop()
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	observed := len(r.state.records)
	deadline := time.Now().Add(idle)
	timer := time.AfterFunc(idle, wake)
	defer timer.Stop()
	for len(r.state.records) < n {
		if err := ctx.Err(); err != nil {
			return cloneRecords(r.state.records), err
		}
		if len(r.state.records) > observed {
			observed = len(r.state.records)
			deadline = r.state.lastRecord.Add(idle)
			timer.Reset(time.Until(deadline))
		}
		if !time.Now().Before(deadline) {
			return cloneRecords(r.state.records), context.DeadlineExceeded
		}
		r.state.cond.Wait()
	}
	return cloneRecords(r.state.records), nil
}

// Deadline returns a fresh operation deadline, bounded by ctx's overall deadline.
func Deadline(ctx context.Context, idle time.Duration) time.Time {
	deadline := time.Now().Add(idle)
	if overall, ok := ctx.Deadline(); ok && overall.Before(deadline) {
		return overall
	}
	return deadline
}

// RecordsWithMessage returns only the named records, preserving duplicates.
func (r *Recorder) RecordsWithMessage(message string) []slog.Record {
	var result []slog.Record
	for _, record := range r.Records() {
		if record.Message == message {
			result = append(result, record)
		}
	}
	return result
}
