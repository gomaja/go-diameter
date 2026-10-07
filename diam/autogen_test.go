package diam

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAutogenExportsIdentifiers(t *testing.T) {
	requireAutogenTools(t)
	dir := t.TempDir()
	for _, name := range []string{"dict/bundled", "avp"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0750); err != nil {
			t.Fatal(err)
		}
	}
	script, err := os.ReadFile("autogen.sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "autogen.sh"), script, 0600); err != nil {
		t.Fatal(err)
	}
	const fixture = `<diameter>
<application id="123" type="auth" name="lowercase app">
<command code="456" short="lc" name="lowercase-command">
<request/>
<answer/>
</command>
<avp name="eDRX-Related-RAT" code="1705"><data type="Grouped"/></avp>
<avp name="eDRX-Cycle-Length" code="1691"><data type="Unsigned32"/></avp>
<avp name="9-Test" code="999"><data type="Unsigned32"/></avp>
</application>
</diameter>`
	if err := os.WriteFile(filepath.Join(dir, "dict/bundled/fixture.xml"), []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "autogen.sh")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("autogen: %v\n%s", err, out)
	}
	expected := map[string][]string{
		"commands.go":     {"Lowercasecommand", "LcR", "LcA"},
		"applications.go": {"LOWERCASE_APP_APP_ID"},
		"avp/codes.go":    {"EDRXRelatedRAT", "EDRXCycleLength", "X9Test"},
	}
	for name, want := range expected {
		seen := make(map[string]bool)
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			g, ok := decl.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, spec := range g.Specs {
				for _, id := range spec.(*ast.ValueSpec).Names {
					seen[id.Name] = true
					if !id.IsExported() {
						t.Errorf("%s: generated identifier %s is not exported", name, id.Name)
					}
				}
			}
		}
		for _, id := range want {
			if !seen[id] {
				t.Errorf("%s: missing generated identifier %s", name, id)
			}
		}
	}
}

// requireAutogenTools skips the test where autogen.sh cannot run: it needs a
// POSIX shell, sort, the go command, and GNU sed for the \u replacement,
// which it takes from gsed on macOS.
func requireAutogenTools(t *testing.T) {
	t.Helper()
	sed := "sed"
	if runtime.GOOS == "darwin" {
		sed = "gsed"
	}
	for _, tool := range []string{"sh", "sort", "go", sed} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("autogen.sh needs %s: %v", tool, err)
		}
	}
}

// TestGeneratedFilesAreCurrent runs autogen.sh on the bundled dictionaries
// and requires the committed constants to match, so a dictionary change
// cannot land without the constants it generates.
func TestGeneratedFilesAreCurrent(t *testing.T) {
	requireAutogenTools(t)
	dir := t.TempDir()
	for _, name := range []string{"dict/bundled", "avp"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0750); err != nil {
			t.Fatal(err)
		}
	}
	copyFile := func(src, dst string) {
		t.Helper()
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	copyFile("autogen.sh", filepath.Join(dir, "autogen.sh"))
	xml, err := filepath.Glob(filepath.Join("dict", "bundled", "*.xml"))
	if err != nil || len(xml) == 0 {
		t.Fatalf("bundled dictionaries: %v %v", xml, err)
	}
	for _, src := range xml {
		copyFile(src, filepath.Join(dir, "dict", "bundled", filepath.Base(src)))
	}
	cmd := exec.Command("sh", "autogen.sh")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("autogen: %v\n%s", err, out)
	}
	for _, name := range []string{"commands.go", "applications.go", filepath.Join("avp", "codes.go")} {
		want, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		// A Windows checkout may convert the committed files to CRLF.
		if g, w := lf(got), lf(want); g != w {
			gl, wl := strings.Split(g, "\n"), strings.Split(w, "\n")
			i := 0
			for i < len(gl) && i < len(wl) && gl[i] == wl[i] {
				i++
			}
			var gotLine, wantLine string
			if i < len(gl) {
				gotLine = gl[i]
			}
			if i < len(wl) {
				wantLine = wl[i]
			}
			t.Errorf("%s is out of date at line %d: have %q, generated %q; run sh autogen.sh in diam/", name, i+1, gotLine, wantLine)
		}
	}
}

func lf(b []byte) string { return strings.ReplaceAll(string(b), "\r\n", "\n") }
