package sm

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/diamtest"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/logtest"
)

func TestStateMachineLogsEveryUnhandledMessage(t *testing.T) {
	const count = 5000
	for _, mode := range []int{0, -1} {
		for _, request := range []bool{true, false} {
			t.Run(fmt.Sprintf("concurrency=%d/request=%t", mode, request), func(t *testing.T) {
				const idle = 30 * time.Second
				ctx := t.Context()
				if deadline, ok := t.Deadline(); ok {
					var cancel context.CancelFunc
					ctx, cancel = context.WithDeadline(ctx, deadline)
					defer cancel()
				}
				records := logtest.New()
				sm := mustNewStateMachine(t, testMessageErrorSettings())
				srv := diamtest.NewUnstartedServer(sm, dict.Default)
				srv.Config.Logger = records.Logger()
				srv.Config.MaxConcurrentHandlers = mode
				srv.Start()
				defer srv.Close()
				var workers sync.WaitGroup
				for peer := 0; peer < 4; peer++ {
					workers.Add(1)
					go func() {
						defer workers.Done()
						c, err := net.Dial("tcp", srv.Addr)
						if err != nil {
							t.Error(err)
							return
						}
						defer func() { _ = c.Close() }()
						if err = c.SetDeadline(logtest.Deadline(ctx, idle)); err != nil {
							t.Error(err)
							return
						}
						if _, err = regressionCER(t, dict.Default, 1001).WriteTo(c); err != nil {
							t.Error(err)
							return
						}
						if a, e := diam.ReadMessage(c, dict.Default); e != nil || !testResultCode(a, diam.Success) {
							t.Errorf("CER: %v %v", a, e)
							return
						}
						for i := 0; i < count/4; i++ {
							if err := c.SetDeadline(logtest.Deadline(ctx, idle)); err != nil {
								t.Error(err)
								return
							}
							id := uint32(peer*(count/4) + i + 1)
							flags := uint8(0)
							if request {
								flags = diam.RequestFlag
							}
							m := diam.NewMessage(0xfedc, flags, 0, id, id+count, dict.Default)
							if _, err = m.WriteTo(c); err != nil {
								t.Error(err)
								return
							}
							if request {
								a, e := diam.ReadMessage(c, dict.Default)
								if e != nil {
									t.Error(e)
									return
								}
								if a.Header.HopByHopID != id || a.Header.EndToEndID != id+count || a.Header.CommandFlags != diam.ErrorFlag || !testResultCode(a, diam.CommandUnsupported) {
									t.Errorf("unsupported reply: %v", a)
									return
								}
							}
						}
					}()
				}
				workers.Wait()
				got, err := records.WaitProgress(ctx, count, idle)
				if err != nil {
					t.Fatalf("records %d/%d: %v", len(got), count, err)
				}
				srv.Close()
				got = records.Records()
				if len(got) != count {
					t.Fatalf("records=%d want %d", len(got), count)
				}
				seen := make(map[uint64]bool, count)
				for _, r := range got {
					wantLevel, wantMessage := slog.LevelWarn, "sm: unhandled answer discarded"
					if request {
						wantLevel, wantMessage = slog.LevelInfo, "sm: unsupported command answered"
					}
					if r.Level != wantLevel || r.Message != wantMessage {
						t.Fatalf("unexpected record %v", r)
					}
					if request && logtest.Attr(r, "result_code").Uint64() != diam.CommandUnsupported {
						t.Fatalf("result code missing: %v", r)
					}
					id := logtest.Attr(r, "message.hop_by_hop_id").Uint64()
					if id == 0 || id > count || seen[id] {
						t.Fatalf("duplicate/unknown Hop-by-Hop ID %d", id)
					}
					seen[id] = true
					for _, attr := range []string{"network", "local_addr", "remote_addr"} {
						if !logtest.HasAttr(r, attr) {
							t.Fatalf("missing connection attribute %s", attr)
						}
					}
				}
			})
		}
	}
}

func TestStateMachineRegistrationPanics(t *testing.T) {
	noop := diam.HandlerFunc(func(diam.Conn, *diam.Message) {})
	for _, cmd := range []struct {
		name string
		idx  diam.CommandIndex
	}{{"CER", baseCERIdx}, {"CEA", baseCEAIdx}, {"DWR", baseDWRIdx}, {"DPR", baseDPRIdx}, {"DPA", baseDPAIdx}} {
		for _, api := range []string{"Handle", "HandleFunc", "HandleIdx"} {
			t.Run(cmd.name+"/"+api, func(t *testing.T) {
				sm := mustNewStateMachine(t, testMessageErrorSettings())
				defer func() {
					if recover() == nil {
						t.Fatal("reserved registration did not panic")
					}
				}()
				switch api {
				case "Handle":
					sm.Handle(cmd.name, noop)
				case "HandleFunc":
					sm.HandleFunc(cmd.name, noop)
				case "HandleIdx":
					sm.HandleIdx(cmd.idx, noop)
				}
			})
		}
	}
	for _, tc := range []struct {
		name     string
		register func(*StateMachine)
	}{
		{"typed nil Handle", func(sm *StateMachine) { sm.Handle("XYZ", diam.HandlerFunc(nil)) }},
		{"typed nil HandleIdx", func(sm *StateMachine) { sm.HandleIdx(diam.CommandIndex{Code: 999}, diam.HandlerFunc(nil)) }},
		{"nil Handle", func(sm *StateMachine) { sm.Handle("XYZ", nil) }},
		{"nil HandleFunc", func(sm *StateMachine) { sm.HandleFunc("XYZ", nil) }},
		{"nil HandleIdx", func(sm *StateMachine) { sm.HandleIdx(diam.CommandIndex{Code: 999}, nil) }},
		{"empty", func(sm *StateMachine) { sm.Handle("", noop) }},
		{"duplicate", func(sm *StateMachine) { sm.Handle("XYZ", noop); sm.Handle("XYZ", noop) }},
		{"duplicate index", func(sm *StateMachine) {
			idx := diam.CommandIndex{Code: 999}
			sm.HandleIdx(idx, noop)
			sm.HandleIdx(idx, noop)
		}},
		{"ALL", func(sm *StateMachine) { sm.Handle("ALL", noop); sm.HandleIdx(diam.ALL_CMD_INDEX, noop) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sm := mustNewStateMachine(t, testMessageErrorSettings())
			defer func() {
				failure := recover()
				if failure == nil {
					t.Fatal("invalid registration did not panic")
				}
				if strings.HasPrefix(tc.name, "nil ") && !strings.Contains(fmt.Sprint(failure), "nil handler") {
					t.Fatalf("nil handler panic = %v", failure)
				}
			}()
			tc.register(sm)
		})
	}
}
