// Copyright 2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const header = `{"config":{"protocol_version":"v1.0.0","scan_level":"module","scan_mode":"source"}}
{"SBOM":{"go_version":"go1.27.2","modules":[{"path":"example.test/gate","version":"(devel)"}]}}
`

func finding(id string) string {
	return fmt.Sprintf(`{"finding":{"osv":%q,"trace":[{"module":"golang.org/x/crypto","version":"v0.58.0"}]}}`+"\n", id)
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name, json, deps, wantErr string
		wantIDs                   string
	}{
		{name: "no findings", json: header, deps: "fmt\nexample.test/gate\n"},
		{name: "known module finding", json: header + finding("GO-2026-5932"), deps: "golang.org/x/crypto/sha3\n", wantIDs: "GO-2026-5932"},
		{name: "duplicate finding", json: header + finding("GO-2026-5932") + finding("GO-2026-5932"), deps: "fmt\n", wantIDs: "GO-2026-5932"},
		{name: "metadata is not a finding", json: header + `{"osv":{"id":"GO-2026-9999"}}`, deps: "fmt\n"},
		{name: "second finding", json: header + finding("GO-2026-5932") + finding("GO-2026-9999"), deps: "fmt\n", wantErr: "GO-2026-9999"},
		{name: "other finding alone", json: header + finding("GO-2026-9999"), deps: "fmt\n", wantErr: "GO-2026-9999"},
		{name: "openpgp root even without findings", json: header, deps: "fmt\ngolang.org/x/crypto/openpgp\n", wantErr: "OpenPGP dependency"},
		{name: "openpgp subpackage", json: header, deps: "golang.org/x/crypto/openpgp/packet\n", wantErr: "OpenPGP dependency"},
		{name: "openpgp test import", json: header, deps: "golang.org/x/crypto/openpgp [example.test/gate.test]\n", wantErr: "OpenPGP dependency"},
		{name: "prefix lookalike", json: header + finding("GO-2026-5932"), deps: "golang.org/x/crypto/openpgpish\ngolang.org/x/crypto/openpgp-other/packet\n", wantIDs: "GO-2026-5932"},
		{name: "empty JSON", deps: "fmt\n", wantErr: "configuration"},
		{name: "truncated JSON", json: header + `{"finding":`, deps: "fmt\n", wantErr: "JSON"},
		{name: "trailing garbage", json: header + "broken", deps: "fmt\n", wantErr: "JSON"},
		{name: "missing SBOM", json: strings.Split(header, "\n")[0], deps: "fmt\n", wantErr: "SBOM"},
		{name: "wrong scan level", json: strings.Replace(header, `"module"`, `"package"`, 1), deps: "fmt\n", wantErr: "module source scan"},
		{name: "wrong protocol", json: strings.Replace(header, "v1.0.0", "v2.0.0", 1), deps: "fmt\n", wantErr: "protocol"},
		{name: "finding before configuration", json: finding("GO-2026-5932") + header, deps: "fmt\n", wantErr: "configuration"},
		{name: "repeated configuration", json: header + header, deps: "fmt\n", wantErr: "configuration"},
		{name: "empty message", json: header + `{}`, deps: "fmt\n", wantErr: "one field"},
		{name: "multiple fields", json: header + `{"finding":{"osv":"GO-2026-5932"},"progress":{}}`, deps: "fmt\n", wantErr: "one field"},
		{name: "unknown message", json: header + `{"error":{"message":"failure"}}`, deps: "fmt\n", wantErr: "unknown message"},
		{name: "null finding", json: header + `{"finding":null}`, deps: "fmt\n", wantErr: "finding"},
		{name: "missing ID", json: header + `{"finding":{"trace":[{"module":"golang.org/x/crypto"}]}}`, deps: "fmt\n", wantErr: "finding"},
		{name: "missing trace", json: header + `{"finding":{"osv":"GO-2026-5932"}}`, deps: "fmt\n", wantErr: "finding"},
		{name: "package finding", json: header + `{"finding":{"osv":"GO-2026-5932","trace":[{"module":"golang.org/x/crypto","package":"golang.org/x/crypto/openpgp"}]}}`, deps: "fmt\n", wantErr: "module finding"},
		{name: "empty dependency output", json: header, wantErr: "dependency output"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, err := check(strings.NewReader(tt.json), strings.NewReader(tt.deps), moduleScan{main: "example.test/gate"})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(ids, ","); got != tt.wantIDs {
				t.Fatalf("finding IDs = %q, want %q", got, tt.wantIDs)
			}
		})
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	jsonPath, depsPath := filepath.Join(dir, "module.json"), filepath.Join(dir, "deps.txt")
	for path, data := range map[string]string{jsonPath: header + finding("GO-2026-5932"), depsPath: "fmt\n"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	inventoryPath := filepath.Join(dir, "modules.json")
	if err := os.WriteFile(inventoryPath, []byte(`{"Path":"example.test/gate","Main":true,"Dir":`+strconv.Quote(dir)+`}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{jsonPath, depsPath, dir, inventoryPath}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "GO-2026-5932") || !strings.Contains(out.String(), "OpenPGP absent (including tests)") {
		t.Fatalf("missing per-run evidence: %q", out.String())
	}
	for _, args := range [][]string{nil, {jsonPath}, {jsonPath, depsPath, "extra"}, {"missing", depsPath}, {jsonPath, "missing"}} {
		if err := run(args, &out); err == nil {
			t.Fatalf("run(%q) succeeded", args)
		}
	}
}
