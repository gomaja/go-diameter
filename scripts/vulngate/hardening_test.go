// Copyright 2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestInactiveOpenPGPImports(t *testing.T) {
	for _, tc := range []struct{ name, file, source string }{
		{"windows test", "openpgp_windows_test.go", "package fixture\nimport _ \"golang.org/x/crypto/openpgp\"\n"},
		{"custom tag", "sub/tagged.go", "//go:build customtag\n\npackage fixture\nimport _ \"golang.org/x/crypto/openpgp/packet\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFixture(t, dir, tc.file, tc.source)
			jsonPath := writeFixture(t, dir, "scan.json", header+finding(allowedID))
			depsPath := writeFixture(t, dir, "deps.txt", "fmt\nexample.test/gate\n")
			inventoryPath := writeFixture(t, dir, "modules.json", `{"Path":"example.test/gate","Main":true,"Dir":`+strconv.Quote(dir)+`}`)
			var out bytes.Buffer
			if err := run([]string{jsonPath, depsPath, dir, inventoryPath}, &out); err == nil || !strings.Contains(err.Error(), "OpenPGP") {
				t.Fatalf("inactive forbidden import accepted: error=%v output=%q", err, out.String())
			}
		})
	}
}

func writeFixture(t *testing.T, dir, name, source string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScannerJSONHardening(t *testing.T) {
	config := strings.Split(header, "\n")[0] + "\n"
	for _, tc := range []struct{ name, input string }{
		{"case alias osv", header + `{"finding":{"OSV":"GO-2026-9999","osv":"GO-2026-5932","trace":[{"module":"golang.org/x/crypto"}]}}`},
		{"case alias SBOM", config + `{"SBOM":{"modules":[{"path":"example.test/gate","VERSION":"(devel)"}]}}`},
		{"duplicate osv", header + `{"finding":{"osv":"GO-2026-9999","osv":"GO-2026-5932","trace":[{"module":"golang.org/x/crypto"}]}}`},
		{"escaped duplicate key", header + `{"finding":{"osv":"GO-2026-9999","\u006fsv":"GO-2026-5932","trace":[{"module":"golang.org/x/crypto"}]}}`},
		{"duplicate in metadata array", header + `{"osv":{"affected":[{"database_specific":{"x":1,"x":2}}]}}`},
		{"duplicate config", strings.Replace(header, `"scan_level":"module"`, `"scan_level":"package","scan_level":"module"`, 1)},
		{"malformed SBOM", config + `{"SBOM":{"modules":"not a module list"}}`},
		{"null module", config + `{"SBOM":{"modules":[null]}}`},
		{"empty module path", config + `{"SBOM":{"modules":[{"path":"","version":"v1.0.0"}]}}`},
		{"missing module version", config + `{"SBOM":{"modules":[{"path":"example.test/gate"}]}}`},
		{"empty module version", config + `{"SBOM":{"modules":[{"path":"example.test/gate","version":""}]}}`},
		{"wrong version type", config + `{"SBOM":{"modules":[{"path":"example.test/gate","version":2}]}}`},
		{"SBOM without main module", config + `{"SBOM":{"modules":[{"path":"stdlib","version":"v1.27.2"}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := check(strings.NewReader(tc.input), strings.NewReader("fmt\n"), moduleScan{main: "example.test/gate"}); err == nil {
				t.Fatal("unexpected scanner JSON accepted")
			}
		})
	}
}

func TestStrictScansIncludeTests(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("check.sh command fixture requires Linux")
	}
	script, err := filepath.Abs("../check.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"symbol", "package"} {
		t.Run(level, func(t *testing.T) {
			dir := t.TempDir()
			writeFixture(t, dir, "oteldiam/go.mod", "module example.test/otel\n")
			writeFixture(t, dir, "dnsdiam/go.mod", "module example.test/dns\n")
			writeFixture(t, dir, "diam/a.go", "package diam\n")
			goStub := `#!/bin/bash
if [[ "$1" == env ]]; then echo /tmp; exit 0; fi
if [[ "$1" == list ]]; then echo example.test/gate; exit 0; fi
if [[ "$*" == *govulncheck* ]]; then
 if [[ "$*" == *"-scan $FIXTURE_LEVEL"* && " $* " == *" -test "* ]]; then
  echo 'test-only fixture vulnerability detected' >&2; exit 9
 fi
 if [[ "$*" == *"-scan module"* ]]; then printf '%s\n' "$FIXTURE_JSON"; fi
 exit 0
fi
exit 0
`
			bin := filepath.Join(dir, "bin")
			goPath := writeFixture(t, bin, "go", goStub)
			gitPath := writeFixture(t, bin, "git", "#!/bin/bash\nprintf '%s\\n' \"$FIXTURE_ROOT\"\n")
			for _, path := range []string{goPath, gitPath} {
				if err := os.Chmod(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", script, "vuln")
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "GO_STABLE=go1.27.2", "GO_OLDSTABLE=go1.26.9", "FIXTURE_ROOT="+dir, "FIXTURE_LEVEL="+level, "FIXTURE_JSON="+header)
			out, err := cmd.CombinedOutput()
			if err == nil || !bytes.Contains(out, []byte("test-only fixture vulnerability detected")) {
				t.Fatalf("strict %s scan missed test-only finding: %v\n%s", level, err, out)
			}
		})
	}
}
