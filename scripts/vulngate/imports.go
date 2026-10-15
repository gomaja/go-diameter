// Copyright 2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func forbiddenPackage(path string) bool {
	return path == openpgp || strings.HasPrefix(path, openpgp+"/")
}

// Parse imports irrespective of filename constraints and build tags. Nested
// modules are checked separately; testdata and vendor are outside this rule.
func checkImports(root string) error {
	set := token.NewFileSet()
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("reading module sources: %w", err)
		}
		if entry.IsDir() {
			if path != root {
				if entry.Name() == "testdata" || entry.Name() == "vendor" {
					return filepath.SkipDir
				}
				_, err := os.Stat(filepath.Join(path, "go.mod"))
				if err == nil {
					return filepath.SkipDir
				}
				if !os.IsNotExist(err) {
					return fmt.Errorf("checking module boundary: %w", err)
				}
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		file, err := parser.ParseFile(set, path, nil, parser.ImportsOnly|parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parsing module imports: %w", err)
		}
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return fmt.Errorf("invalid import at %s: %w", set.Position(spec.Pos()), err)
			}
			if forbiddenPackage(imported) {
				return fmt.Errorf("forbidden OpenPGP import %q at %s (all build configurations)", imported, set.Position(spec.Pos()))
			}
		}
		return nil
	})
}
