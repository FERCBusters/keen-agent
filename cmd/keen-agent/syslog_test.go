package main

import (
	"testing"
	"time"
)

func TestJournalIdentityAndClassification(t *testing.T) {
	e := parse(Config{}, Source{Name: "system", Parser: "syslog"}, "2026/10/06 06:07:56 health: ingestion returned HTTP 400", time.Now())
	e.Fields["_SYSTEMD_UNIT"] = "keen-agent.service"
	e.Fields["SYSLOG_IDENTIFIER"] = "keen-agent"
	e.Fields["PRIORITY"] = "6"
	normalizeJournal(&e)
	if e.Action != "agent.heartbeat.failed" || e.Outcome != "failure" || e.Fields["service.name"] != "keen-agent.service" || e.Fields["http.status_code"] != "400" {
		t.Fatal(e)
	}
}
func TestCronInvocationIsNotSuccess(t *testing.T) {
	e := parse(Config{}, Source{Name: "system", Parser: "syslog"}, "Oct  6 06:07:56 host CRON[123]: (root) CMD (/usr/local/bin/backup)", time.Now())
	if e.Action != "scheduled_job.started" || e.Outcome != "info" || e.Fields["job.command"] != "/usr/local/bin/backup" || e.Actor != "root" {
		t.Fatal(e)
	}
}
func TestUnrelatedProgramCannotClaimAgentAction(t *testing.T) {
	e := parse(Config{}, Source{Name: "system", Parser: "syslog"}, "health: ingestion returned HTTP 400", time.Now())
	e.Fields["SYSLOG_IDENTIFIER"] = "other"
	normalizeJournal(&e)
	if e.Action != "syslog.record" || e.Outcome != "info" {
		t.Fatal(e)
	}
}

func TestNginxEvidenceFieldsAndTime(t *testing.T) {
	e := parse(Config{}, Source{Name: "nginx-access", Parser: "nginx"}, `35.221.69.202 - - [05/Oct/2026:02:18:12 +0000] "GET /.aws/config HTTP/1.1" 404 146 "-" "bot"`, time.Now())
	if e.Timestamp.Format(time.RFC3339) != "2026-10-05T02:18:12Z" || e.Fields["path"] != "/.aws/config" || e.Fields["status"] != "404" || e.Fields["http.method"] != "GET" {
		t.Fatal(e)
	}
}
