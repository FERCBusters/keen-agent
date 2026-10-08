package main

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var auditID = regexp.MustCompile(`audit\(([0-9]+(?:\.[0-9]+)?):([0-9]+)\)`)
var kv = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=("[^"\n]*"|'[^'\n]*'|[^\s]+)`)
var dpkg = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (install|upgrade|remove|purge|status) (.*)$`)
var nginxTimestamp = regexp.MustCompile(`\[([0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9:]+ [+-][0-9]{4})\]`)
var nginxMethod = regexp.MustCompile(`"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) `)
var nginx = regexp.MustCompile(`"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ([^ ]+) HTTP/[^" ]+" ([0-9]{3})`)

func parse(c Config, s Source, raw string, ts time.Time) Event {
	if s.Parser == "ossec" {
		raw = c.redactOSSEC(raw)
	} else {
		raw = c.redact(raw)
	}
	e := Event{ID: uuid(), Timestamp: ts.UTC(), Source: s.Name, Action: s.Parser + ".record", Outcome: "info", Severity: 3, Raw: raw, Fields: map[string]string{"parser": s.Parser}}
	e.Summary = raw
	if len(e.Summary) > 2000 {
		e.Summary = string([]rune(e.Summary)[:min(1000, len([]rune(e.Summary)))])
	}
	switch s.Parser {
	case "ossec":
		parseOSSEC(&e)
	case "syslog":
		// RFC 5424 and ISO timestamps retain their zone. RFC 3164 uses host local time
		// and the nearest previous year at a New Year boundary.
		text := raw
		if strings.HasPrefix(text, "<") {
			if i := strings.Index(text, ">"); i > 0 {
				text = text[i+1:]
			}
		}
		parts := strings.Fields(text)
		for i := 0; i < min(2, len(parts)); i++ {
			if t, err := time.Parse(time.RFC3339Nano, parts[i]); err == nil {
				e.Timestamp = t.UTC()
				break
			}
		}
		if len(text) >= 15 {
			if t, err := time.ParseInLocation("Jan _2 15:04:05 2006", text[:15]+" "+strconv.Itoa(ts.Year()), time.Local); err == nil {
				if t.After(ts.Add(24 * time.Hour)) {
					t = t.AddDate(-1, 0, 0)
				}
				e.Timestamp = t.UTC()
			}
		}
		normalizeSyslogText(&e)
	case "auditd":
		if m := auditID.FindStringSubmatch(raw); m != nil {
			seconds, _ := strconv.ParseFloat(m[1], 64)
			e.Timestamp = time.Unix(int64(seconds), int64((seconds-float64(int64(seconds)))*1e9)).UTC()
			e.Fields["audit_id"] = m[1] + ":" + m[2]
		}
		for _, m := range kv.FindAllStringSubmatch(raw, 64) {
			v := strings.Trim(m[2], "\"'")
			if len(v) <= 4096 {
				if _, exists := e.Fields[m[1]]; exists {
					continue
				}
				e.Fields[m[1]] = v
			}
		}
		if t := e.Fields["type"]; t != "" {
			e.Action = "auditd." + t
		}
		e.Actor = e.Fields["auid"]
		if e.Fields["success"] == "yes" || e.Fields["res"] == "success" {
			e.Outcome = "success"
		}
		if e.Fields["success"] == "no" || e.Fields["res"] == "failed" {
			e.Outcome = "failure"
			e.Severity = 6
		}
	case "dpkg":
		if m := dpkg.FindStringSubmatch(raw); m != nil {
			if t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local); err == nil {
				e.Timestamp = t.UTC()
			}
			e.Action = "package." + m[2]
			parts := strings.Fields(m[3])
			if m[2] == "status" && len(parts) >= 2 {
				e.Fields["package_status"] = parts[0]
				parts = parts[1:]
			}
			if len(parts) > 0 {
				e.Fields["package"] = parts[0]
			}
			if len(parts) > 1 {
				if m[2] == "status" {
					e.Fields["version"] = parts[1]
				} else {
					e.Fields["old_version"] = parts[1]
				}
			}
			if len(parts) > 2 {
				e.Fields["new_version"] = parts[2]
			}
		}
	case "apt":
		e.Action = "package.transaction"
		for _, line := range strings.Split(raw, "\n") {
			for _, key := range []string{"Start-Date", "End-Date", "Requested-By", "Install", "Upgrade", "Remove", "Purge", "Downgrade"} {
				if strings.HasPrefix(line, key+":") {
					v := strings.TrimSpace(strings.TrimPrefix(line, key+":"))
					e.Fields[strings.ToLower(strings.ReplaceAll(key, "-", "_"))] = v
					if key == "Start-Date" {
						parts := strings.Fields(v)
						if len(parts) == 2 {
							if t, err := time.ParseInLocation("2006-01-02 15:04:05", strings.Join(parts, " "), time.Local); err == nil {
								e.Timestamp = t.UTC()
							}
						}
					}
				}
			}
		}
		if strings.Contains(raw, "End-Date:") {
			e.Fields["transaction_end_recorded"] = "true"
		}
		if strings.Contains(strings.ToLower(raw), "error") {
			e.Outcome = "failure"
		}
	case "dnf":
		e.Action = "package.record"
		for _, action := range []string{"Installed:", "Upgraded:", "Removed:", "Erased:", "Downgraded:"} {
			if i := strings.Index(raw, action); i >= 0 {
				e.Action = "package." + strings.ToLower(strings.TrimSuffix(action, ":"))
				e.Fields["package"] = strings.TrimSpace(raw[i+len(action):])
				break
			}
		}
	case "nginx":
		// Standard combined/common access format: first token is logged remote_addr.
		// Do not infer addresses from forwarded headers or later request fields.
		if parts := strings.Fields(raw); len(parts) > 0 {
			if addr, err := netip.ParseAddr(parts[0]); err == nil && addr.Zone() == "" {
				e.Fields["client.ip"] = addr.String()
			}
		}
		if m := nginxTimestamp.FindStringSubmatch(raw); m != nil {
			if stamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[1]); err == nil {
				e.Timestamp = stamp.UTC()
			}
		}
		if m := nginxMethod.FindStringSubmatch(raw); m != nil {
			e.Fields["http.method"] = m[1]
		}
		if m := nginx.FindStringSubmatch(raw); m != nil {
			e.Action = "http.request"
			e.Fields["path"] = strings.SplitN(m[1], "?", 2)[0]
			e.Fields["status"] = m[2]
			if strings.HasPrefix(m[2], "5") {
				e.Outcome = "failure"
				e.Severity = 6
			}
		}
	case "php":
		e.Action = "php.log"
		if strings.Contains(raw, "Fatal error") || strings.Contains(raw, "PHP Parse error") {
			e.Outcome = "failure"
			e.Severity = 6
		}
	case "json":
		var fields map[string]any
		if json.Unmarshal([]byte(raw), &fields) == nil {
			keys := []string{}
			for k := range fields {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := fields[k]
				if len(e.Fields) >= 60 {
					break
				}
				if len(k) > 128 {
					continue
				}
				b, _ := json.Marshal(v)
				if len(b) <= 4096 {
					e.Fields[k] = string(b)
				}
			}
		} else {
			e.Fields["parse_status"] = "invalid_json"
		}
	}
	if len(e.Actor) > 128 {
		e.Actor = ""
	}
	// Bound enrichment independently of raw evidence. Keep deterministic keys on replay.
	keys := []string{}
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	size := 0
	for _, k := range keys {
		v := e.Fields[k]
		encoded, _ := json.Marshal(map[string]string{k: v})
		size += len(encoded)
		if len(k) > 110 || len(v) > 4096 || size > 10000 {
			delete(e.Fields, k)
			e.Fields["enrichment_truncated"] = "true"
		}
	}
	if len(e.Action) > 128 {
		e.Action = s.Parser + ".record"
	}
	return e
}
