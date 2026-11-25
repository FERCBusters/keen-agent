package main

import (
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Helpers shared by the parsers of one-JSON-object-per-line logs (OSSEC
// alerts, Tetragon events). The records are data only: numbers stay exact,
// and nothing in them can name a field the collector itself sets.

// jsonRecords reports whether a parser's lines are JSON objects, redacted
// after their string escapes are decoded.
func jsonRecords(parser string) bool {
	return parser == "ossec" || parser == "tetragon"
}

func jsonLookup(data map[string]any, path string) any {
	var current any = data
	for _, key := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[key]
	}
	return current
}

func jsonValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func jsonObject(raw string, data *map[string]any) bool {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(data) != nil || *data == nil {
		return false
	}
	var extra any
	return decoder.Decode(&extra) == io.EOF
}

// Decode string escapes before applying redaction, then serialize safely. The
// iterative walk avoids recursive traversal of attacker-supplied object nesting.
func (c Config) redactJSON(raw string) string {
	if len(c.redactors) == 0 {
		return c.redact(raw)
	}
	var data map[string]any
	if !jsonObject(raw, &data) {
		return c.redact(raw)
	}
	pending := []any{data}
	for len(pending) > 0 {
		item := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		switch value := item.(type) {
		case map[string]any:
			keys := make([]string, 0, len(value))
			for key := range value {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				child := value[key]
				if text, ok := child.(string); ok {
					child = c.redact(text)
				} else {
					pending = append(pending, child)
				}
				safeKey := c.redact(key)
				if safeKey != key {
					delete(value, key)
				}
				value[safeKey] = child
			}
		case []any:
			for i, child := range value {
				if text, ok := child.(string); ok {
					value[i] = c.redact(text)
				} else {
					pending = append(pending, child)
				}
			}
		}
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return "[JSON record could not be safely redacted]"
	}
	return c.redact(string(encoded))
}
