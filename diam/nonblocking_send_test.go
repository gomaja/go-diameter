package diam

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Notification channels may coalesce wake-ups. Reports and handshake callbacks
// may not disappear because a receiver is slow. Keep this list tied to the
// channel's purpose rather than source line numbers, which drift on edits.
func TestNonblockingSendsHaveDocumentedReason(t *testing.T) {
	allowed := map[string]string{
		"server.go:c.idle":            "Idle notification coalesces; the consumer reads the current activity state.",
		"sm/disconnect.go:p.result":   "Disconnect completion is a one-shot result; a buffered result already completes the waiter.",
		"sm/dwa.go:dwac":              "Watchdog acknowledgement is a coalescing wake-up, not an error report.",
		"sm/watchdog.go:s.signal":     "Read activity coalesces; activity state is stored separately.",
		"peer/session.go:s.ingress":   "Queue overflow is reported and the connection closes.",
		"peer/session.go:s.writes":    "Queue overflow is returned to the writer for reporting and closure.",
		"peer/manager.go:m.callbackQ": "Dropped peer events are explicitly logged before returning.",
	}
	seen := make(map[string]bool)
	files := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(files, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selection, ok := node.(*ast.SelectStmt)
			if !ok {
				return true
			}
			hasDefault := false
			for _, stmt := range selection.Body.List {
				if stmt.(*ast.CommClause).Comm == nil {
					hasDefault = true
				}
			}
			if !hasDefault {
				return true
			}
			for _, stmt := range selection.Body.List {
				send, ok := stmt.(*ast.CommClause).Comm.(*ast.SendStmt)
				if !ok {
					continue
				}
				var channel bytes.Buffer
				if err := printer.Fprint(&channel, files, send.Chan); err != nil {
					t.Error(err)
					continue
				}
				key := filepath.ToSlash(path) + ":" + channel.String()
				if reason, ok := allowed[key]; !ok || reason == "" {
					t.Errorf("%s: nonblocking send %s needs a documented reason", files.Position(send.Pos()), key)
				} else {
					seen[key] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for key := range allowed {
		if !seen[key] {
			t.Errorf("stale nonblocking send allow-list entry: %s", key)
		}
	}
}
