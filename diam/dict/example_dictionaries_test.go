package dict_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/gomaja/go-diameter/diam/dict/all"
)

// TestExampleDictionariesLoad loads every dictionary the examples ship, so
// the strict loader cannot reject one without a test failing.
func TestExampleDictionariesLoad(t *testing.T) {
	var files []string
	err := filepath.WalkDir(filepath.Join("..", "..", "examples"), func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(path) == ".xml" {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no example dictionaries found")
	}
	for _, path := range files {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := newTestParser(t, all.Dictionary()).Load(bytes.NewReader(b)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
