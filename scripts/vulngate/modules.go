// Copyright 2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

type moduleScan struct {
	main  string
	local map[string]bool
}

// Source scans omit versions for local code. Corroborate only those entries
// against successful go list -m -json all output; never invent a remote version.
func readModules(reader io.Reader, root string) (moduleScan, error) {
	scan := moduleScan{local: make(map[string]bool)}
	dec := json.NewDecoder(reader)
	for {
		object, err := readObject(dec)
		if err == io.EOF {
			break
		}
		if err != nil {
			return scan, fmt.Errorf("invalid module inventory: %w", err)
		}
		path, err := requiredString(object["Path"], "module path")
		if err != nil {
			return scan, err
		}
		var main bool
		if err := json.Unmarshal(object["Main"], &main); err != nil && object["Main"] != nil {
			return scan, err
		}
		if main {
			if scan.main != "" {
				return scan, fmt.Errorf("multiple main modules")
			}
			dir, err := requiredString(object["Dir"], "main module directory")
			if err != nil {
				return scan, err
			}
			if filepath.Clean(dir) != root {
				return scan, fmt.Errorf("main module directory %q differs from source root %q", dir, root)
			}
			scan.main = path
			scan.local[path] = true
		}
		if replace := object["Replace"]; replace != nil {
			replacement, err := objectPayload(replace)
			if err != nil {
				return scan, err
			}
			path, err := requiredString(replacement["Path"], "replacement path")
			if err != nil {
				return scan, err
			}
			if path == "." || path == ".." || filepath.IsAbs(path) || strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
				if _, err := requiredString(replacement["Dir"], "local replacement directory"); err != nil {
					return scan, err
				}
				scan.local[path] = true
			}
		}
	}
	if scan.main == "" {
		return scan, fmt.Errorf("module inventory has no main module")
	}
	return scan, nil
}

func checkSBOM(raw json.RawMessage, scan moduleScan) error {
	object, err := objectPayload(raw)
	if err != nil {
		return fmt.Errorf("invalid SBOM: %w", err)
	}
	if err := canonicalKeys(object, "go_version", "modules", "roots"); err != nil {
		return err
	}
	var modules []json.RawMessage
	if err := json.Unmarshal(object["modules"], &modules); err != nil {
		return fmt.Errorf("invalid SBOM modules: %w", err)
	}
	if len(modules) == 0 {
		return fmt.Errorf("empty SBOM modules")
	}
	main := false
	for _, raw := range modules {
		module, err := objectPayload(raw)
		if err != nil {
			return fmt.Errorf("invalid SBOM module: %w", err)
		}
		if err := canonicalKeys(module, "path", "version"); err != nil {
			return err
		}
		path, err := requiredString(module["path"], "SBOM module path")
		if err != nil {
			return err
		}
		version, err := requiredString(module["version"], "SBOM module version")
		// Only omitted versions, not explicit empty/null/wrongly typed ones, may
		// become a development version backed by the independently loaded graph.
		if module["version"] == nil && scan.local[path] {
			version = "(devel)"
			err = nil
		}
		if err != nil || strings.TrimSpace(version) == "" {
			return fmt.Errorf("invalid SBOM version for %q: %v", path, err)
		}
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("empty SBOM module path")
		}
		if path == scan.main {
			main = true
		}
	}
	if !main {
		return fmt.Errorf("SBOM does not contain scanned module %q", scan.main)
	}
	return nil
}
