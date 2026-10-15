// Copyright 2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestImportDeclarations(t *testing.T) {
	for _, tc := range []struct {
		name, path, source string
		bad                bool
	}{
		{"active root", "a.go", `package p; import _ "golang.org/x/crypto/openpgp"`, true},
		{"subpackage raw literal", "sub/a.go", "package p; import alias `golang.org/x/crypto/openpgp/packet`", true},
		{"escaped import", "a.go", `package p; import _ "golang.org/x/crypto/open\x70gp"`, true},
		{"comment and string", "a.go", `package p; import "fmt"; // import "golang.org/x/crypto/openpgp"
var source = "golang.org/x/crypto/openpgp"`, false},
		{"prefix lookalike", "a.go", `package p; import _ "golang.org/x/crypto/openpgpish"`, false},
		{"testdata", "sub/testdata/a.go", `package p; import _ "golang.org/x/crypto/openpgp"`, false},
		{"vendor", "vendor/a.go", `package p; import _ "golang.org/x/crypto/openpgp"`, false},
		{"broken import", "a_windows.go", `package p; import (`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFixture(t, dir, tc.path, tc.source)
			err := checkImports(dir)
			if (err != nil) != tc.bad {
				t.Fatalf("checkImports: %v, want rejection=%v", err, tc.bad)
			}
		})
	}
	t.Run("module boundaries", func(t *testing.T) {
		dir := t.TempDir()
		writeFixture(t, dir, "child/go.mod", "module child\n")
		child := writeFixture(t, dir, "child/a.go", `package p; import _ "golang.org/x/crypto/openpgp"`)
		if err := checkImports(dir); err != nil {
			t.Fatal(err)
		}
		if err := checkImports(filepath.Dir(child)); err == nil {
			t.Fatal("separately checked child module was ignored")
		}
	})
	if err := checkImports("does-not-exist"); err == nil {
		t.Fatal("missing module source accepted")
	}
}

func TestModuleEvidence(t *testing.T) {
	root := t.TempDir()
	main := `{"Path":"example.test/gate","Main":true,"Dir":` + strconv.Quote(root) + `}`
	local := `{"Path":"example.test/dep","Version":"v1.0.0","Replace":{"Path":"../","Dir":` + strconv.Quote(root) + `}}`
	scan, err := readModules(strings.NewReader(main+local), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkSBOM(json.RawMessage(`{"modules":[{"path":"example.test/gate"},{"path":"../"},{"path":"remote.test/dep","version":"v1.0.0"}]}`), scan); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"modules":[{"path":"example.test/gate","version":"(devel)"},{"path":"remote.test/dep"}]}`,
		`{"modules":[{"path":"example.test/gate","version":""}]}`,
		`{"modules":[{"path":"example.test/gate","version":null}]}`,
		`{"modules":[{"path":"example.test/gate","version":"   "}]}`,
		`{"modules":[{"path":"example.test/gate","VERSION":"bogus"}]}`,
	} {
		if err := checkSBOM(json.RawMessage(raw), scan); err == nil {
			t.Fatalf("invalid module evidence accepted: %s", raw)
		}
	}
	// Build the wrong directory directly: on Windows the quoted root in main
	// has doubled backslashes, so replacing root inside it would not match.
	wrongDir := `{"Path":"example.test/gate","Main":true,"Dir":` + strconv.Quote(filepath.Join(root, "wrong")) + `}`
	for _, raw := range []string{"", local, main + main, wrongDir, strings.Replace(main, `"Main":true`, `"Main":true,"Main":true`, 1), `{"Path":"a","Replace":{"Path":"../"}}`} {
		if _, err := readModules(strings.NewReader(raw), root); err == nil {
			t.Fatalf("invalid independent inventory accepted: %s", raw)
		}
	}
}

func FuzzDuplicateJSONKeys(f *testing.F) {
	for _, key := range []string{"osv", "modules", "\\u006fsv", "<key>"} {
		f.Add(key)
	}
	f.Fuzz(func(t *testing.T, key string) {
		encoded, err := json.Marshal(key)
		if err != nil {
			t.Fatal(err)
		}
		raw := `{"outer":[{` + string(encoded) + `:"GO-2026-9999",` + string(encoded) + `:"GO-2026-5932"}]}`
		if _, err := objectPayload(json.RawMessage(raw)); err == nil {
			t.Fatal("duplicate key accepted")
		}
	})
}
