package main

import (
	"encoding/json"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// OSSEC alert JSON is data only. Enrichment uses bounded namespaced fields;
// event IDs and collector credentials never come from the alert payload.
func parseOSSEC(e *Event) {
	var data map[string]any
	if !ossecObject(e.Raw, &data) {
		e.Fields["parse_status"] = "invalid_json"
		return
	}
	get := func(path string) string { return ossecValue(ossecLookup(data, path)) }
	first := func(paths ...string) string {
		for _, path := range paths {
			if value := get(path); value != "" {
				return value
			}
		}
		return ""
	}
	e.Action = "ossec.alert"
	put := func(key, value string) {
		if value != "" {
			e.Fields[key] = value
		}
	}
	put("ossec.alert.id", get("id"))
	put("ossec.rule.id", first("rule.id", "rule.sidid", "rule.sid"))
	put("ossec.rule.level", get("rule.level"))
	put("ossec.rule.description", first("rule.description", "rule.comment"))
	put("ossec.rule.firedtimes", get("rule.firedtimes"))
	put("ossec.agent.id", get("agent.id"))
	put("ossec.manager.name", get("manager.name"))
	put("host.name", first("agent.name", "agent_name", "hostname"))
	put("ossec.location", first("location", "logfile"))
	put("ossec.decoder.name", first("decoder.name", "decoder_desc.name"))
	put("process.name", first("data.program_name", "program_name"))
	put("user.name", first("data.srcuser", "srcuser", "data.dstuser", "dstuser", "data.user", "user"))
	e.Actor = e.Fields["user.name"]
	for _, item := range []struct {
		key   string
		paths []string
	}{
		{"source.ip", []string{"data.srcip", "srcip"}},
		{"destination.ip", []string{"data.dstip", "dstip"}},
		{"host.ip", []string{"agent.ip", "agentip"}},
	} {
		if ip, err := netip.ParseAddr(first(item.paths...)); err == nil && ip.Zone() == "" {
			put(item.key, ip.Unmap().String())
		}
	}
	put("client.ip", e.Fields["source.ip"])
	put("source.port", first("data.srcport", "srcport"))
	put("destination.port", first("data.dstport", "dstport"))
	put("file.path", first("syscheck.path", "SyscheckFile.path"))
	put("ossec.syscheck.event", first("syscheck.event", "SyscheckFile.event"))
	for _, key := range []string{"md5_before", "md5_after", "sha1_before", "sha1_after", "sha256_before", "sha256_after", "size_before", "size_after", "perm_before", "perm_after", "uid_before", "uid_after", "gid_before", "gid_after"} {
		put("ossec.syscheck."+key, first("syscheck."+key, "SyscheckFile."+key))
	}
	if description := e.Fields["ossec.rule.description"]; description != "" {
		e.Summary = description
	}
	if level, err := strconv.Atoi(get("rule.level")); err == nil && level >= 0 && level <= 16 {
		// Preserve the vendor level; KEEN's severity is 0..10.
		e.Severity = min(10, (level*10+7)/15)
	}
	if stamp, ok := ossecTime(data); ok {
		e.Timestamp = stamp.UTC()
	} else {
		e.Fields["timestamp_status"] = "collection_time_fallback"
	}
	groups := ossecGroups(ossecLookup(data, "rule.groups"))
	if len(groups) > 0 {
		encoded, _ := json.Marshal(groups)
		put("ossec.rule.groups", string(encoded))
	}
	has := func(group string) bool {
		for _, g := range groups {
			if g == group {
				return true
			}
		}
		return false
	}
	// Use explicit rule classification, never an arbitrary substring of full_log.
	switch {
	case has("syscheck") || e.Fields["file.path"] != "":
		e.Action = "file.integrity.alert"
		switch e.Fields["ossec.syscheck.event"] {
		case "added":
			e.Action = "file.created"
		case "modified":
			e.Action = "file.changed"
		case "deleted":
			e.Action = "file.deleted"
		}
	case has("rootcheck"):
		e.Action = "host.integrity.alert"
	case has("authentication_failed") || has("authentication_failures") || has("authentication_failure"):
		e.Action = "auth.login"
		e.Outcome = "failure"
	case has("authentication_success"):
		e.Action = "auth.login"
		e.Outcome = "success"
	}
	// Preserve bounded vendor-specific leaves for custom rules. Curated aliases
	// remain deterministic and payload keys cannot replace collector provenance.
	flattenOSSEC(e.Fields, "ossec.data", data["data"], 0)
	if len(e.Summary) > 2000 {
		e.Summary = string([]rune(e.Summary)[:min(1000, len([]rune(e.Summary)))])
	}
}

func ossecLookup(data map[string]any, path string) any {
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
func ossecValue(value any) string {
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
func ossecGroups(value any) []string {
	groups := []string{}
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				groups = append(groups, s)
			}
		}
	case string:
		groups = strings.Split(v, ",")
	}
	unique := map[string]bool{}
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group != "" && len(group) <= 128 {
			unique[group] = true
		}
	}
	groups = groups[:0]
	for group := range unique {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	if len(groups) > 32 {
		groups = groups[:32]
	}
	return groups
}
func ossecTime(data map[string]any) (time.Time, bool) {
	// Legacy TimeStamp is epoch milliseconds; prefer it over zone-less text.
	if value := ossecValue(data["TimeStamp"]); value != "" {
		if ms, err := strconv.ParseInt(value, 10, 64); err == nil && ms > 0 && ms <= 9223372036854 {
			return time.UnixMilli(ms), true
		}
	}
	text := ossecValue(data["timestamp"])
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700", "2006 Jan 02 15:04:05", "2006 Jan _2 15:04:05"} {
		if stamp, err := time.ParseInLocation(layout, text, time.Local); err == nil && stamp.Year() >= 1970 && stamp.Year() < 2262 {
			return stamp, true
		}
	}
	return time.Time{}, false
}
func flattenOSSEC(fields map[string]string, prefix string, value any, depth int) {
	if depth > 4 || len(fields) >= 55 {
		return
	}
	if object, ok := value.(map[string]any); ok {
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if len(key) <= 64 && !strings.ContainsAny(key, ".\x00\r\n") {
				flattenOSSEC(fields, prefix+"."+key, object[key], depth+1)
			}
		}
	} else if text := ossecValue(value); text != "" && len(prefix) <= 110 && len(text) <= 4096 {
		fields[prefix] = text
	}
}

func ossecObject(raw string, data *map[string]any) bool {
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
func (c Config) redactOSSEC(raw string) string {
	if len(c.redactors) == 0 {
		return c.redact(raw)
	}
	var data map[string]any
	if !ossecObject(raw, &data) {
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
		return "[OSSEC JSON could not be safely redacted]"
	}
	return c.redact(string(encoded))
}
