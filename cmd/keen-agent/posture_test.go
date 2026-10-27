package main

import (
	"encoding/json"
	"keen-agent/internal/posture"
	"os"
	"strings"
	"testing"
	"time"
)

func postureEvent(check string, host bool) Event {
	o := posture.Observation{Version: 1, Check: check, Provider: "test", Scope: "host", Status: "observed", Reason: "test", Facts: map[string]string{"enabled": "true"}}
	b, _ := json.Marshal(o)
	e := Event{Raw: string(b), Timestamp: time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC), Fields: map[string]string{"_TRANSPORT": "stdout"}}
	if host {
		e.Fields["_UID"] = "0"
		e.Fields["_SYSTEMD_UNIT"] = "keen-posture-host.service"
	} else {
		e.Fields["_UID"] = "1000"
		e.Fields["_SYSTEMD_USER_UNIT"] = "keen-posture-session.service"
	}
	return e
}
func TestPostureAuthorityBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, check string
		host        bool
		change      func(*Event)
		want        bool
	}{
		{"host_disk", "disk_encryption", true, nil, true}, {"user_lock", "screen_lock", false, nil, true},
		{"user_cannot_attest_disk", "disk_encryption", false, nil, false}, {"root_cannot_impersonate_session", "screen_lock", true, nil, false},
		{"user_host_unit_name", "disk_encryption", true, func(e *Event) { e.Fields["_UID"] = "1000" }, false},
		{"missing_uid", "disk_encryption", true, func(e *Event) { delete(e.Fields, "_UID") }, false},
		{"forged_syslog_transport", "disk_encryption", true, func(e *Event) { e.Fields["_TRANSPORT"] = "syslog" }, false},
		{"wrong_unit", "disk_encryption", true, func(e *Event) { e.Fields["_SYSTEMD_UNIT"] = "other.service" }, false},
		{"trailing_json", "disk_encryption", true, func(e *Event) { e.Raw += " {}" }, false},
		{"reserved_fact", "screen_lock", false, func(e *Event) { e.Raw = strings.Replace(e.Raw, `"enabled":"true"`, `"authority":"host_root"`, 1) }, false},
		{"unknown_payload_field", "disk_encryption", true, func(e *Event) { e.Raw = strings.TrimSuffix(e.Raw, "}") + `,"uid":0}` }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := postureEvent(tc.check, tc.host)
			if tc.change != nil {
				tc.change(&e)
			}
			err := normalizePosture(&e)
			if (err == nil) != tc.want {
				t.Fatalf("error=%v event=%+v", err, e)
			}
			if err == nil {
				if e.Outcome != "info" || e.Fields["posture.status"] != "observed" {
					t.Fatal(e)
				}
				if e.Fields["posture.subject_uid"] != e.Actor {
					t.Fatal(e)
				}
			}
		})
	}
}
func TestPostureOTLPUsesExistingFields(t *testing.T) {
	e := postureEvent("screen_lock", false)
	e.ID = uuid()
	if err := normalizePosture(&e); err != nil {
		t.Fatal(err)
	}
	payload := string(otlp([]Event{e}))
	for _, v := range []string{"keen.field.posture.authority", "user_session", "keen.field.posture.observed_at", "posture.screen_lock"} {
		if !strings.Contains(payload, v) {
			t.Fatal(payload)
		}
	}
}
func FuzzPostureJournal(f *testing.F) {
	f.Add(postureEvent("screen_lock", false).Raw)
	f.Fuzz(func(t *testing.T, raw string) {
		e := postureEvent("screen_lock", false)
		e.Raw = raw
		err := normalizePosture(&e)
		if err == nil && (e.Action != "posture.screen_lock" || e.Fields["posture.authority"] != "user_session") {
			t.Fatal(e)
		}
	})
}

func TestPostureConfigRejectsFileAndCustomUnits(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		valid        bool
	}{
		{"journal", "kind: journal\n    parser: posture", true},
		{"file", "kind: file\n    parser: posture\n    paths: [/var/log/posture.json]", false},
		{"units", "kind: journal\n    parser: posture\n    units: [untrusted.service]", false},
		{"paths", "kind: journal\n    parser: posture\n    paths: [/var/log/posture.json]", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := t.TempDir() + "/config.yaml"
			raw := "endpoint: https://keen.example/api/v1/otlp/logs\ntoken_file: /etc/keen-agent/token\nsources:\n  - name: posture\n    " + tc.source + "\n"
			if e := os.WriteFile(p, []byte(raw), 0600); e != nil {
				t.Fatal(e)
			}
			_, e := config(p)
			if (e == nil) != tc.valid {
				t.Fatal(e)
			}
		})
	}
}
func TestHostQubesContext(t *testing.T) {
	e := postureEvent("screen_lock", true)
	o := posture.QubesContext("session")
	b, _ := json.Marshal(o)
	e.Raw = string(b)
	if err := normalizePosture(&e); err != nil {
		t.Fatal(err)
	}
	if e.Fields["posture.control_location"] != "qubes_gui_domain" || e.Fields["posture.enabled"] != "" {
		t.Fatal(e)
	}
}
