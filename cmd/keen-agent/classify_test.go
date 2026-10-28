package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"keen-agent/internal/ueu"
)

func sealerFor(t *testing.T, mode, ceiling string) *sealer {
	t.Helper()
	id := testIdentity(t, "https://keen.example/api/v1/otlp/logs")
	id.Ceiling = ceiling
	z, err := newSealer(Config{EvidenceMode: mode}, id)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func classify(t *testing.T, z *sealer, s Source, line string) []map[string]any {
	t.Helper()
	e := parse(Config{}, s, line, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	e.Ref = "file:/var/log/test@10"
	envs, err := z.envelopes(s, e)
	if err != nil {
		t.Fatal(err)
	}
	return envs
}

func canonical(t *testing.T, env map[string]any) string {
	b, err := ueu.Canonical(env)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const dpkgLine = "2026-01-01 00:00:00 upgrade example:amd64 1.0 1.1"

func TestModesDecideWhatIsSent(t *testing.T) {
	dpkg := Source{Name: "dpkg", Parser: "dpkg"}
	nginx := Source{Name: "nginx", Parser: "nginx"}
	access := `192.0.2.1 - - [01/Jan/2026:00:00:00 +0000] "GET /x HTTP/1.1" 200 1`

	events := sealerFor(t, "events", "all_lines")
	envs := classify(t, events, dpkg, dpkgLine)
	if len(envs) != 1 || envs[0]["event_type"] != "software.package.changed" {
		t.Fatal(envs)
	}
	evidence := envs[0]["evidence"].(map[string]any)
	if evidence["payload_included"] != false || evidence["collection_mode"] != "events" || evidence["supporting_record_reference"] != "file:/var/log/test@10" {
		t.Fatal(evidence)
	}
	if strings.Contains(canonical(t, envs[0]), "2026-01-01 00:00:00 upgrade") {
		t.Fatal("line sent in events mode")
	}
	if len(classify(t, events, nginx, access)) != 0 {
		t.Fatal("unrecognised line sent in events mode")
	}

	lines := sealerFor(t, "events_with_lines", "all_lines")
	if p := classify(t, lines, dpkg, dpkgLine)[0]["evidence"].(map[string]any)["payload"]; p != dpkgLine {
		t.Fatal(p)
	}
	if len(classify(t, lines, nginx, access)) != 0 {
		t.Fatal("unrecognised line sent without all_lines")
	}

	all := sealerFor(t, "all_lines", "all_lines")
	envs = classify(t, all, nginx, access)
	if len(envs) != 1 || envs[0]["event_type"] != "log.line.collected" || envs[0]["evidence"].(map[string]any)["payload"] != access {
		t.Fatal(envs)
	}
	attributes := envs[0]["attributes"].(map[string]any)
	if attributes["status"] != "200" || attributes["client.ip"] != nil {
		t.Fatalf("line attributes: %v", attributes)
	}
}

func TestCeilingLimitsTheConfiguredMode(t *testing.T) {
	z := sealerFor(t, "all_lines", "events")
	mode, clamped := z.mode(Source{Name: "nginx"})
	if mode != ueu.ModeEvents || !clamped {
		t.Fatal(mode, clamped)
	}
	if len(classify(t, z, Source{Name: "nginx", Parser: "nginx"}, `192.0.2.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1`)) != 0 {
		t.Fatal("ceiling exceeded")
	}
	m, clamped := z.mode(Source{Name: "x", EvidenceMode: "events"})
	if m != ueu.ModeEvents || clamped {
		t.Fatal(m, clamped)
	}
}

func TestRecognisedEvents(t *testing.T) {
	z := sealerFor(t, "events", "events")
	for _, tc := range []struct {
		name, parser, line, eventType string
		attributes                    map[string]any
		subject                       bool
	}{
		{"dpkg", "dpkg", dpkgLine, "software.package.changed", map[string]any{"manager": "dpkg", "action": "upgrade", "package": "example:amd64", "old_version": "1.0", "new_version": "1.1"}, false},
		{"dnf", "dnf", "2026-01-01T00:00:00+0000 SUBDEBUG Upgraded: openssl-3.0.2-1.x86_64", "software.package.changed", map[string]any{"manager": "dnf", "action": "upgraded"}, false},
		{"sshd", "syslog", "Jan  1 00:00:00 web sshd[42]: Accepted publickey for alice from 192.0.2.4 port 22 ssh2", "user.authenticated", map[string]any{"service": "sshd", "method": "publickey"}, true},
		{"sudo", "syslog", "Jan  1 00:00:00 web sudo[7]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update", "privileged.action.completed", map[string]any{"mechanism": "sudo", "executable": "apt"}, true},
		{"denied", "auditd", `type=SYSCALL msg=audit(1791240000.001:12): arch=c000003e syscall=2 success=no exit=-13 auid=1000 exe="/usr/bin/cat"`, "access.denied", map[string]any{"syscall": "2", "executable": "cat", "audit_type": "SYSCALL"}, true},
		{"ossec", "ossec", ossecModern, "security.alert.generated", map[string]any{"rule_id": "5715", "level": int64(3), "description": "Login accepted"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envs := classify(t, z, Source{Name: tc.name, Parser: tc.parser}, tc.line)
			if len(envs) != 1 || envs[0]["event_type"] != tc.eventType {
				t.Fatalf("%v", envs)
			}
			got := envs[0]["attributes"].(map[string]any)
			for k, v := range tc.attributes {
				if got[k] != v {
					t.Fatalf("%s=%v (%T), want %v; %v", k, got[k], got[k], v, got)
				}
			}
			if _, ok := envs[0]["subject"]; ok != tc.subject {
				t.Fatalf("subject present=%v", ok)
			}
			text := canonical(t, envs[0])
			for _, secret := range []string{"alice", "192.0.2.4"} {
				if strings.Contains(text, secret) {
					t.Fatalf("%q disclosed: %s", secret, text)
				}
			}
		})
	}
	// Successful syscalls and status lines are activity, not catalogue events.
	if len(classify(t, z, Source{Name: "audit", Parser: "auditd"}, `type=SYSCALL msg=audit(1.0:1): success=yes`)) != 0 {
		t.Fatal("successful syscall became an event")
	}
	if len(classify(t, z, Source{Name: "dpkg", Parser: "dpkg"}, "2026-01-01 00:00:00 status installed example:amd64 1.1")) != 0 {
		t.Fatal("dpkg status became an event")
	}
}

func TestAptTransactionListsPackagesAndPseudonymisesRequester(t *testing.T) {
	z := sealerFor(t, "events", "events")
	line := "Start-Date: 2026-01-01  00:00:00\nRequested-By: alice (1000)\nUpgrade: openssl:amd64 (3.0.1, 3.0.2), curl:amd64 (8.0, 8.1)\nInstall: jq:amd64 (1.7)\nEnd-Date: 2026-01-01  00:00:05"
	envs := classify(t, z, Source{Name: "apt", Parser: "apt"}, line)
	if len(envs) != 1 {
		t.Fatal(envs)
	}
	b, _ := json.Marshal(envs[0]["attributes"].(map[string]any)["packages"])
	if string(b) != `["install:jq:amd64","upgrade:openssl:amd64","upgrade:curl:amd64"]` {
		t.Fatal(string(b))
	}
	if envs[0]["attributes"].(map[string]any)["transaction_complete"] != true || envs[0]["subject"] == nil || strings.Contains(canonical(t, envs[0]), "alice") {
		t.Fatal(envs[0])
	}
}

func TestDiscardIsRecorded(t *testing.T) {
	s := testSpool(t)
	s.add(envelopesFor(t, s, rawSource, event(), event()), "file", Checkpoint{Offset: 5})
	d, err := s.purgeQueue()
	if err != nil || d.count != 2 || d.first != 1 || d.last != 2 {
		t.Fatal(d, err)
	}
	if err = s.recordDiscard(d); err != nil {
		t.Fatal(err)
	}
	batch, _ := s.batch()
	if len(batch) != 1 || batch[0].EventType != "evidence.records.discarded" || batch[0].Sequence != 3 {
		t.Fatal(batch)
	}
	attributes := decoded(t, batch[0])["attributes"].(map[string]any)
	if attributes["count"].(float64) != 2 || attributes["first_sequence"].(float64) != 1 || attributes["reason"] != "operator_purge" {
		t.Fatal(attributes)
	}
}
