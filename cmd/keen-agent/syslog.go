package main

import (
	"regexp"
	"strconv"
	"strings"
)

var syslogHeader = regexp.MustCompile(`^(?:<[0-9]+>)?(?:[A-Z][a-z]{2}\s+[0-9]+\s+[0-9:]+|[0-9]{4}-\S+)\s+(\S+)\s+([A-Za-z0-9_.@/-]+)(?:\[([0-9]+)\])?:\s*(.*)$`)
var cronCommand = regexp.MustCompile(`^\(([^)]+)\) CMD \((.*)\)$`)
var agentFailure = regexp.MustCompile(`(?:^|\s)health: ingestion returned HTTP ([0-9]{3})(?:$|\s)`)

func normalizeSyslogText(e *Event) {
	message := e.Raw
	if m := syslogHeader.FindStringSubmatch(message); m != nil {
		e.Fields["host.name"] = m[1]
		e.Fields["process.name"] = m[2]
		if m[3] != "" {
			e.Fields["process.pid"] = m[3]
		}
		message = m[4]
	}
	classifySyslog(e, message)
}
func normalizeJournal(e *Event) {
	for raw, normalized := range map[string]string{"_SYSTEMD_UNIT": "service.name", "SYSLOG_IDENTIFIER": "process.name", "_PID": "process.pid", "_UID": "user.id", "_GID": "group.id", "_HOSTNAME": "host.name"} {
		if value := e.Fields[raw]; value != "" {
			e.Fields[normalized] = value
		}
	}
	if e.Fields["process.name"] == "" {
		e.Fields["process.name"] = e.Fields["_COMM"]
	}
	if priority, err := strconv.Atoi(e.Fields["PRIORITY"]); err == nil && priority >= 0 && priority <= 7 {
		e.Fields["log.syslog.priority"] = strconv.Itoa(priority)
		e.Severity = []int{10, 9, 8, 7, 5, 4, 3, 2}[priority]
	}
	classifySyslog(e, e.Raw)
}
func classifySyslog(e *Event, message string) {
	program := strings.ToLower(e.Fields["process.name"])
	service := e.Fields["service.name"]
	if program == "keen-agent" || service == "keen-agent.service" {
		if m := agentFailure.FindStringSubmatch(message); m != nil {
			e.Action = "agent.heartbeat.failed"
			e.Outcome = "failure"
			e.Severity = 6
			e.Fields["http.status_code"] = m[1]
		} else if strings.Contains(message, " health: ") || strings.HasPrefix(message, "health: ") {
			e.Action = "agent.heartbeat.failed"
			e.Outcome = "failure"
			e.Severity = 6
		} else if strings.Contains(message, "delivery progress:") {
			e.Action = "agent.delivery.progress"
		} else if strings.Contains(message, "delivery:") && strings.Contains(message, "retry_in=") {
			e.Action = "agent.delivery.failed"
			e.Outcome = "failure"
			e.Severity = 6
		}
	}
	if program == "cron" || program == "crond" || program == "crond-session" {
		if m := cronCommand.FindStringSubmatch(message); m != nil {
			e.Action = "scheduled_job.started"
			e.Outcome = "info"
			e.Actor = m[1]
			e.Fields["user.name"] = m[1]
			e.Fields["job.command"] = m[2]
		}
	}
	if program == "sshd" || program == "sshd-session" {
		if strings.HasPrefix(message, "Accepted publickey for ") || strings.HasPrefix(message, "Accepted password for ") {
			e.Action = "authentication.accepted"
			e.Outcome = "success"
		} else if strings.HasPrefix(message, "Failed password for ") || strings.HasPrefix(message, "Failed publickey for ") {
			e.Action = "authentication.failed"
			e.Outcome = "failure"
			e.Severity = 6
		}
	}
}
