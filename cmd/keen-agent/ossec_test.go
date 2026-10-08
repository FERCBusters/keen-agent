package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const ossecLegacy = `{"rule":{"level":7,"comment":"Login rejected","sidid":5701,"groups":["syslog","authentication_failed"]},"TimeStamp":1791338400123,"timestamp":"2026 Oct 07 10:00:00","hostname":"web.example","agentip":"192.0.2.5","srcip":"198.51.100.6","dstuser":"alice","id":"1791338400.42","full_log":"failed login"}`
const ossecModern = `{"timestamp":"2026-10-07T10:00:00.123+1100","rule":{"level":3,"description":"Login accepted","id":"5715","groups":["sshd","authentication_success"]},"agent":{"id":"007","name":"web.example","ip":"192.0.2.5"},"manager":{"name":"manager.example"},"data":{"srcip":"2001:db8::2","srcuser":"alice","srcport":"22","custom":{"result":"allowed"}},"full_log":"accepted login"}`

func TestOSSECLegacyAndModern(t *testing.T) {
	legacy := parse(Config{}, Source{Name: "ossec", Parser: "ossec"}, ossecLegacy, time.Now())
	if legacy.Action != "auth.login" || legacy.Outcome != "failure" || legacy.Actor != "alice" || legacy.Fields["ossec.rule.id"] != "5701" || legacy.Fields["host.name"] != "web.example" || legacy.Timestamp.UnixMilli() != 1791338400123 {
		t.Fatal(legacy)
	}
	modern := parse(Config{}, Source{Name: "ossec", Parser: "ossec"}, ossecModern, time.Now())
	if modern.Action != "auth.login" || modern.Outcome != "success" || modern.Fields["source.ip"] != "2001:db8::2" || modern.Fields["ossec.manager.name"] != "manager.example" || modern.Fields["ossec.data.custom.result"] != "allowed" || modern.Timestamp.Format(time.RFC3339Nano) != "2026-10-06T23:00:00.123Z" {
		t.Fatal(modern)
	}
	if !strings.Contains(string(otlp([]Event{modern})), `keen.field.ossec.rule.id`) {
		t.Fatal("OSSEC fields missing on wire")
	}
}
func TestOSSECIntegrityAndUnknownOutcomes(t *testing.T) {
	for _, root := range []string{"syscheck", "SyscheckFile"} {
		raw := `{"timestamp":"2026-10-07T00:00:00Z","rule":{"level":12,"groups":["syscheck"]},"` + root + `":{"event":"modified","path":"/etc/ssh/sshd_config","sha256_before":"abc","sha256_after":"def"}}`
		e := parse(Config{}, Source{Parser: "ossec"}, raw, time.Now())
		if e.Action != "file.changed" || e.Outcome != "info" || e.Fields["file.path"] != "/etc/ssh/sshd_config" || e.Fields["ossec.syscheck.sha256_after"] != "def" || e.Severity != 8 {
			t.Fatal(e)
		}
	}
	e := parse(Config{}, Source{Parser: "ossec"}, `{"rule":{"groups":["rootcheck"]},"full_log":"authentication_success"}`, time.Now())
	if e.Action != "host.integrity.alert" || e.Outcome != "info" {
		t.Fatal(e)
	}
}
func TestOSSECInvalidAndBoundedInput(t *testing.T) {
	now := time.Now().UTC()
	for _, raw := range []string{`no json`, `null`, `[]`, `{"rule":1} {}`, `{"rule":`} {
		e := parse(Config{}, Source{Parser: "ossec"}, raw, now)
		if e.Fields["parse_status"] != "invalid_json" || e.Raw != raw {
			t.Fatal(e)
		}
	}
	e := parse(Config{}, Source{Parser: "ossec"}, `{"timestamp":"invalid","rule":{"id":9007199254740993,"level":999},"srcip":"not an IP"}`, now)
	if e.Fields["ossec.rule.id"] != "9007199254740993" || !e.Timestamp.Equal(now) || e.Fields["source.ip"] != "" || e.Severity != 3 {
		t.Fatal(e)
	}
	data := map[string]any{}
	for i := 0; i < 200; i++ {
		data[strings.Repeat("x", i+1)] = strings.Repeat("y", 5000)
	}
	encoded, _ := json.Marshal(map[string]any{"data": data, "rule": map[string]any{"id": "42"}})
	e = parse(Config{}, Source{Parser: "ossec"}, string(encoded), now)
	if len(e.Fields) > 60 || e.Fields["ossec.rule.id"] != "42" {
		t.Fatal("unbounded or lost curated fields")
	}
}
func TestOSSECRedactionAndFilters(t *testing.T) {
	c := Config{redactors: []*regexp.Regexp{regexp.MustCompile("secret")}}
	e := parse(c, Source{Parser: "ossec"}, `{"rule":{"comment":"s\u0065cret"},"srcuser":"s\u0065cret","data":{"token":"secret"}}`, time.Now())
	if strings.Contains(e.Raw, "secret") || strings.Contains(e.Summary, "secret") || strings.Contains(e.Actor, "secret") || e.Summary != "[REDACTED]" {
		t.Fatal(e)
	}
	e = parse(Config{}, Source{Parser: "ossec"}, ossecLegacy, time.Now())
	s := Source{ExcludeMatch: "all", ExcludeWhen: []FieldFilter{{"source.ip", "in_cidr", "198.51.100.0/24"}, {"ossec.rule.id", "equals", "5701"}}}
	if keepStructured(s, e) {
		t.Fatal("AND exclusions did not match")
	}
	s.ExcludeWhen[1].Value = "another-rule"
	if !keepStructured(s, e) {
		t.Fatal("partial AND excluded")
	}
	s.ExcludeMatch = "any"
	if keepStructured(s, e) {
		t.Fatal("OR exclusion did not match")
	}
}
func TestOSSECPathBoundariesAndSymlinks(t *testing.T) {
	for _, path := range []string{"/var/ossec/etc/client.keys", "/var/ossec/logs/alerts/../../etc/client.keys", "/var/ossec/logs/alerts-other/x", "relative.log", "/var/log/../../etc/passwd"} {
		if allowedLogPath("ossec", path) {
			t.Fatal(path)
		}
	}
	if !allowedLogPath("ossec", "/var/ossec/logs/alerts/*/*/*.json") || allowedLogPath("json", "/var/ossec/logs/alerts/alerts.json") {
		t.Fatal("wrong permitted roots")
	}
	root := t.TempDir()
	target := filepath.Join(root, "dated.json")
	active := filepath.Join(root, "alerts.json")
	if err := os.WriteFile(target, []byte(ossecLegacy+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dated.json", active); err != nil {
		t.Fatal(err)
	}
	f, err := openLogFile(Source{Parser: "ossec"}, active)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if f, err := openLogFile(Source{Parser: "json"}, active); err == nil {
		f.Close()
		t.Fatal("generic symlink accepted")
	}
	os.Remove(active)
	os.Symlink("../outside", active)
	if f, err := openLogFile(Source{Parser: "ossec"}, active); err == nil {
		f.Close()
		t.Fatal("escaping symlink accepted")
	}
	os.Remove(active)
	os.Symlink("dated-link", active)
	os.Symlink("dated.json", filepath.Join(root, "dated-link"))
	if f, err := openLogFile(Source{Parser: "ossec"}, active); err == nil {
		f.Close()
		t.Fatal("chained symlink accepted")
	}
}
func TestOSSECCollectionRotationAndRedactedSpool(t *testing.T) {
	root := t.TempDir()
	active := filepath.Join(root, "alerts.json")
	first := filepath.Join(root, "first.json")
	os.WriteFile(first, []byte(ossecModern+"\n"), 0600)
	os.Symlink("first.json", active)
	sp := testSpool(t)
	source := Source{Name: "ossec", Parser: "ossec", Kind: "file"}
	c := Config{redactors: []*regexp.Regexp{regexp.MustCompile("alice")}}
	if err := collectFile(c, source, sp, active); err != nil {
		t.Fatal(err)
	}
	if err := collectFile(c, source, sp, first); err != nil {
		t.Fatal(err)
	}
	batch, _ := sp.batch()
	if len(batch) != 1 || strings.Contains(batch[0].Raw, "alice") || batch[0].Actor != "[REDACTED]" {
		t.Fatal(batch)
	}
	id := batch[0].ID
	second := filepath.Join(root, "second.json")
	os.WriteFile(second, []byte(ossecLegacy+"\n"), 0600)
	os.Remove(active)
	os.Symlink("second.json", active)
	if err := collectFile(c, source, sp, active); err != nil {
		t.Fatal(err)
	}
	batch, _ = sp.batch()
	if len(batch) != 2 || batch[0].ID != id {
		t.Fatal("rotation or stable retry identity failed")
	}
}

func TestOSSECConfigAndLegacyTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	text := "endpoint: https://keen.example/api/v1/otlp/logs\ntoken_file: /etc/keen-agent/token\nsources:\n  - name: ossec\n    kind: file\n    parser: ossec\n    paths: [/var/ossec/logs/alerts/alerts.json]\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config(path); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte(strings.ReplaceAll(text, "/var/ossec/logs/alerts/alerts.json", "/var/ossec/etc/client.keys")), 0600)
	if _, err := config(path); err == nil {
		t.Fatal("OSSEC key directory permitted")
	}
	stamp, ok := ossecTime(map[string]any{"timestamp": "2026 Oct 07 10:00:00"})
	if !ok || stamp.In(time.Local).Hour() != 10 {
		t.Fatal(stamp)
	}
	groups := ossecGroups("syslog, authentication_failed,syslog,")
	if len(groups) != 2 || groups[0] != "authentication_failed" {
		t.Fatal(groups)
	}
}
