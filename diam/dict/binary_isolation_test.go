package dict_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Build distinct programs so an all-importing test helper cannot hide linkage
// of an unrelated dictionary in the base-only or single-application program.
func TestBinaryDictionaryIsolation(t *testing.T) {
	// The probe builds small programs, so it needs the go command; test
	// binaries run where no toolchain is installed skip it.
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go command not available: %v", err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile("sources.txt")
	if err != nil {
		t.Fatal(err)
	}
	data := make(map[string][]byte)
	for _, source := range strings.Fields(string(manifest)) {
		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		data[filepath.Base(source)] = content
	}
	allNames := make([]string, 0, len(data))
	for name := range data {
		allNames = append(allNames, name)
	}
	slices.Sort(allNames)
	for _, tc := range []struct {
		name, selector string
		sources        []string
	}{
		{"base", "dict.Base()", []string{"base.xml"}},
		{"gx", "gx.Dictionary()", []string{"base.xml", "credit_control.xml", "gx_credit_control.xml", "network_access_server.xml", "tgpp_ro_rf.xml"}},
		{"s6a", "s6a.Dictionary()", []string{"base.xml", "credit_control.xml", "network_access_server.xml", "tgpp_ro_rf.xml", "tgpp_s6a.xml", "tgpp_s6c.xml"}},
		{"all", "all.Dictionary()", allNames},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			module := "module dictionary-probe\n\ngo 1.26.0\n\nrequire github.com/gomaja/go-diameter v0.0.0\n\nreplace github.com/gomaja/go-diameter => " + strconv.Quote(filepath.ToSlash(root)) + "\n"
			imports := `"fmt"; "github.com/gomaja/go-diameter/diam/dict"`
			if tc.name != "base" {
				imports += `; "github.com/gomaja/go-diameter/diam/dict/` + tc.name + `"`
			}
			program := "package main\nimport (" + imports + ")\nfunc main(){p,err:=dict.New(" + tc.selector + ");if err!=nil{panic(err)};fmt.Println(len(p.Apps()))}\n"
			for name, content := range map[string]string{"go.mod": module, "main.go": program} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			run := func(args ...string) []byte {
				t.Helper()
				cmd := exec.Command(goTool, args...)
				cmd.Dir = dir
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("go %v: %v\n%s", args, err, output)
				}
				return output
			}
			listed := run("list", "-deps", "-json", ".")
			decoder := json.NewDecoder(bytes.NewReader(listed))
			var embedded []string
			for {
				var pkg struct {
					ImportPath string
					EmbedFiles []string
				}
				if err := decoder.Decode(&pkg); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				if !strings.HasPrefix(pkg.ImportPath, "github.com/gomaja/go-diameter/diam/dict") {
					continue
				}
				for _, file := range pkg.EmbedFiles {
					embedded = append(embedded, filepath.Base(file))
				}
			}
			slices.Sort(embedded)
			if !slices.Equal(embedded, tc.sources) {
				t.Fatalf("embedded sources = %v, want %v", embedded, tc.sources)
			}
			executable := filepath.Join(dir, "probe")
			run("build", "-buildvcs=false", "-trimpath", "-ldflags=-s -w", "-o", executable, ".")
			binary, err := os.ReadFile(executable)
			if err != nil {
				t.Fatal(err)
			}
			for name, xml := range data {
				if present, want := bytes.Contains(binary, xml), slices.Contains(tc.sources, name); present != want {
					t.Errorf("binary contains %s = %t, want %t", name, present, want)
				}
			}
			t.Logf("%s: %d bytes", tc.name, len(binary))
		})
	}
}
