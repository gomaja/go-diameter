// Copyright 2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// readObject rejects duplicate keys before any Unmarshal can discard them.
// Token decodes escaped keys too, and nested metadata objects are checked.
func readObject(dec *json.Decoder) (map[string]json.RawMessage, error) {
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	unique := json.NewDecoder(bytes.NewReader(raw))
	unique.UseNumber()
	if err := uniqueValue(unique, 0); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '{' {
		return nil, fmt.Errorf("expected JSON object")
	}
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	return object, nil
}

func uniqueValue(dec *json.Decoder, depth int) error {
	if depth > 1000 {
		return fmt.Errorf("JSON nesting exceeds limit")
	}
	value, err := dec.Token()
	if err != nil {
		return err
	}
	delimiter, container := value.(json.Delim)
	if !container {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]bool)
		for dec.More() {
			token, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			if keys[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[key] = true
			if err := uniqueValue(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := uniqueValue(dec, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = dec.Token()
	return err
}

func requiredString(raw json.RawMessage, field string) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("invalid %s: %w", field, err)
	}
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("empty %s", field)
	}
	return value, nil
}

func objectPayload(raw json.RawMessage) (map[string]json.RawMessage, error) {
	return readObject(json.NewDecoder(bytes.NewReader(raw)))
}

// Go's struct decoding matches keys without regard to case. Reject aliases for
// security-relevant fields so differently cased keys cannot replace each other.
func canonicalKeys(object map[string]json.RawMessage, names ...string) error {
	for key := range object {
		for _, name := range names {
			if key != name && strings.EqualFold(key, name) {
				return fmt.Errorf("noncanonical JSON key %q; expected %q", key, name)
			}
		}
	}
	return nil
}
