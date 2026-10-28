package main

import (
	"encoding/json"
	"keen-agent/internal/posture"
	"keen-agent/internal/posturemodel"
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
		{"unmeasured", "disk_encryption", true, func(e *Event) { e.Raw = strings.Replace(e.Raw, `"observed"`, `"unknown"`, 1) }, false},
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
			if err == nil && (e.Posture == nil || e.Posture.Check != tc.check) {
				t.Fatal(e)
			}
		})
	}
}

func TestSessionObservationBecomesPseudonymousEvidence(t *testing.T) {
	z := sealerFor(t, "events", "events")
	e := postureEvent("screen_lock", false)
	if err := normalizePosture(&e); err != nil {
		t.Fatal(err)
	}
	envs, err := z.envelopes(Source{Name: "posture", Parser: "posture"}, e)
	if err != nil || len(envs) != 1 {
		t.Fatal(envs, err)
	}
	env := envs[0]
	observation := env["observation"].(map[string]any)
	if env["event_type"] != "endpoint.screen_lock.observed" || observation["method"] != "linux_session_collector" || observation["facts"].(map[string]any)["enabled"] != "true" {
		t.Fatal(env)
	}
	if env["subject"].(map[string]any)["identifier_type"] != "pairwise" || strings.Contains(canonical(t, env), `"1000"`) {
		t.Fatal("session UID not pseudonymised")
	}
	host := postureEvent("disk_encryption", true)
	normalizePosture(&host)
	envs, _ = z.envelopes(Source{Name: "posture", Parser: "posture"}, host)
	if _, ok := envs[0]["subject"]; ok || envs[0]["observation"].(map[string]any)["method"] != "linux_host_collector" {
		t.Fatal(envs[0])
	}
}

func TestCoverageLineBecomesCollectionRecord(t *testing.T) {
	z := sealerFor(t, "events", "events")
	all := []posture.Observation{
		{Version: 1, Check: "firewall", Provider: "ufw", Scope: "host", Status: "observed", Reason: "x", Facts: map[string]string{}},
		{Version: 1, Check: "antivirus", Provider: "clamav", Scope: "host", Status: "unknown", Reason: "query_unavailable", Facts: map[string]string{}},
	}
	c := posturemodel.CoverageOf("posture_host", "run_1", all)
	b, _ := json.Marshal(c)
	e := postureEvent("disk_encryption", true)
	e.Raw = string(b)
	if err := normalizePosture(&e); err != nil || e.Coverage == nil {
		t.Fatal(err)
	}
	envs, err := z.envelopes(Source{Name: "posture", Parser: "posture"}, e)
	if err != nil {
		t.Fatal(err)
	}
	a := envs[0]["attributes"].(map[string]any)
	got, _ := json.Marshal([]any{a["checks_attempted"], a["checks_observed"], a["checks_unavailable"], a["probes_unavailable"], a["checks_observed_count"]})
	if envs[0]["event_type"] != "evidence.collection.completed" || string(got) != `[["antivirus","firewall"],["firewall"],["antivirus"],["antivirus/clamav"],1]` {
		t.Fatal(string(got))
	}
	// A desktop session cannot speak for the host collector.
	session := postureEvent("screen_lock", false)
	session.Raw = string(b)
	if normalizePosture(&session) == nil {
		t.Fatal("session reported host coverage")
	}
}

func FuzzPostureJournal(f *testing.F) {
	f.Add(postureEvent("screen_lock", false).Raw)
	f.Fuzz(func(t *testing.T, raw string) {
		e := postureEvent("screen_lock", false)
		e.Raw = raw
		err := normalizePosture(&e)
		if err == nil && (e.Authority != "user_session" || (e.Posture == nil) == (e.Coverage == nil)) {
			t.Fatal(e)
		}
		if err == nil && e.Posture != nil && e.Posture.Check != "screen_lock" {
			t.Fatal("session attested host posture")
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
			_, e := config(writeConfig(t, testConfig+"  - name: posture\n    "+tc.source+"\n"))
			if (e == nil) != tc.valid {
				t.Fatal(e)
			}
		})
	}
}

func TestHostQubesContext(t *testing.T) {
	e := postureEvent("screen_lock", true)
	b, _ := json.Marshal(posture.QubesContext("session"))
	e.Raw = string(b)
	if err := normalizePosture(&e); err != nil {
		t.Fatal(err)
	}
	if e.Posture.Facts["control_location"] != "qubes_gui_domain" || e.Posture.Facts["enabled"] != "" {
		t.Fatal(e.Posture)
	}
}
