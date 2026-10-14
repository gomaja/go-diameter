// Copyright 2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// vulngate checks completed govulncheck module JSON and go list dependency output.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const allowedID = "GO-2026-5932"
const openpgp = "golang.org/x/crypto/openpgp"

// The streaming envelope and fields follow golang.org/x/vuln v1.9.0,
// internal/govulncheck/govulncheck.go (Message, Config and Finding).
// OSV metadata can describe fixed versions too; only finding.osv is a finding.
func check(vulns, deps io.Reader, scan moduleScan) ([]string, error) {
	dec := json.NewDecoder(vulns)
	ids := make(map[string]bool)
	configured, sbom := false, false
	for {
		object, err := readObject(dec)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid govulncheck JSON: %w", err)
		}
		if len(object) != 1 {
			return nil, fmt.Errorf("govulncheck JSON message must have exactly one field")
		}
		var key string
		var payload json.RawMessage
		for name, value := range object {
			key, payload = name, value
		}
		if !configured && key != "config" {
			return nil, fmt.Errorf("govulncheck configuration must be the first message")
		}
		if len(payload) == 0 || payload[0] != '{' {
			return nil, fmt.Errorf("invalid govulncheck %s object", key)
		}
		body, err := objectPayload(payload)
		if err != nil {
			return nil, err
		}
		switch key {
		case "config":
			if configured {
				return nil, fmt.Errorf("repeated govulncheck configuration")
			}
			if err := canonicalKeys(body, "protocol_version", "scan_level", "scan_mode"); err != nil {
				return nil, err
			}
			var cfg struct {
				Protocol string `json:"protocol_version"`
				Level    string `json:"scan_level"`
				Mode     string `json:"scan_mode"`
			}
			if err := json.Unmarshal(payload, &cfg); err != nil {
				return nil, fmt.Errorf("invalid govulncheck configuration: %w", err)
			}
			if cfg.Protocol != "v1.0.0" {
				return nil, fmt.Errorf("unsupported govulncheck protocol %q", cfg.Protocol)
			}
			if cfg.Level != "module" || cfg.Mode != "source" {
				return nil, fmt.Errorf("expected a module source scan, got %q/%q", cfg.Level, cfg.Mode)
			}
			configured = true
		case "SBOM":
			if sbom {
				return nil, fmt.Errorf("repeated govulncheck SBOM")
			}
			if err := checkSBOM(payload, scan); err != nil {
				return nil, err
			}
			sbom = true
		case "progress", "osv":
			// These messages do not indicate vulnerable required versions.
		case "finding":
			if err := canonicalKeys(body, "osv", "fixed_version", "trace"); err != nil {
				return nil, err
			}
			var frames []json.RawMessage
			if err := json.Unmarshal(body["trace"], &frames); err != nil {
				return nil, fmt.Errorf("invalid finding trace: %w", err)
			}
			for _, raw := range frames {
				frame, err := objectPayload(raw)
				if err != nil {
					return nil, err
				}
				if err := canonicalKeys(frame, "module", "version", "package", "function", "receiver", "position"); err != nil {
					return nil, err
				}
			}
			var finding struct {
				OSV   string `json:"osv"`
				Trace []struct {
					Module   string          `json:"module"`
					Package  string          `json:"package"`
					Function string          `json:"function"`
					Receiver string          `json:"receiver"`
					Position json.RawMessage `json:"position"`
				} `json:"trace"`
			}
			if err := json.Unmarshal(payload, &finding); err != nil {
				return nil, fmt.Errorf("invalid govulncheck finding: %w", err)
			}
			if finding.OSV == "" || len(finding.Trace) != 1 || finding.Trace[0].Module == "" {
				return nil, fmt.Errorf("incomplete govulncheck module finding")
			}
			frame := finding.Trace[0]
			if frame.Package != "" || frame.Function != "" || frame.Receiver != "" || len(frame.Position) != 0 {
				return nil, fmt.Errorf("expected a module finding for %s", finding.OSV)
			}
			ids[finding.OSV] = true
		default:
			return nil, fmt.Errorf("unknown message %q in govulncheck JSON", key)
		}
	}
	if !configured {
		return nil, fmt.Errorf("missing govulncheck configuration")
	}
	if !sbom {
		return nil, fmt.Errorf("missing govulncheck SBOM")
	}
	var found []string
	for id := range ids {
		found = append(found, id)
	}
	sort.Strings(found)
	for _, id := range found {
		if id != allowedID {
			return nil, fmt.Errorf("module vulnerability %s is not permitted (finding IDs: %v)", id, found)
		}
	}
	scanner := bufio.NewScanner(deps)
	packages := 0
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		packages++
		// go list -test can append a bracketed test-binary import path.
		pkg := fields[0]
		if forbiddenPackage(pkg) {
			return nil, fmt.Errorf("forbidden OpenPGP dependency %q (including tests)", pkg)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading dependency output: %w", err)
	}
	if packages == 0 {
		return nil, fmt.Errorf("empty dependency output")
	}
	return found, nil
}

func run(args []string, out io.Writer) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: vulngate MODULE.json DEPS.txt MODULE_DIR MODULES.json (all producers must succeed)")
	}
	vulns, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer func() { _ = vulns.Close() }()
	deps, err := os.Open(args[1])
	if err != nil {
		return err
	}
	defer func() { _ = deps.Close() }()
	root, err := filepath.Abs(args[2])
	if err != nil {
		return err
	}
	inventory, err := os.Open(args[3])
	if err != nil {
		return err
	}
	defer func() { _ = inventory.Close() }()
	scan, err := readModules(inventory, root)
	if err != nil {
		return err
	}
	if err := checkImports(root); err != nil {
		return err
	}
	ids, err := check(vulns, deps, scan)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "module finding IDs: %v; OpenPGP absent (including tests); imports checked across all build configurations\n", ids)
	return err
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "module vulnerability gate:", err)
		os.Exit(1)
	}
}
