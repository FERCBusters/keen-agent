package main

import (
	"math"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// Journal and syslog messages recognised beyond SSH logins and sudo: host
// faults, clock synchronisation, name-resolution problems, PHP and Drupal
// errors, account changes, refused access, other failed sign-ins, fail2ban
// bans, the daily apt upgrade job completing and AppArmor loading its profiles
// at boot. Each rule sets the record's action and fields, so filters can select
// them and recognise turns them into catalogue events. Names of people stay in
// user.name, which is pseudonymised as the subject and never sent as text.

// hostRule recognises one kind of message from the named programs, or from
// any program when programs is empty. The first matching rule wins.
type hostRule struct {
	programs string
	pattern  *regexp.Regexp
	apply    func(e *Event, m []string)
}

// set records action and outcome, the fixed fields, and each submatch under
// the field named at its position ("" skips one).
func set(action, outcome string, fixed map[string]string, groups ...string) func(*Event, []string) {
	return func(e *Event, m []string) {
		e.Action, e.Outcome = action, outcome
		if outcome == "failure" {
			e.Severity = 6
		}
		for k, v := range fixed {
			e.Fields[k] = v
		}
		for i, name := range groups {
			if name != "" && i+1 < len(m) && m[i+1] != "" {
				e.Fields[name] = m[i+1]
			}
		}
	}
}

func fault(kind string, groups ...string) func(*Event, []string) {
	return set("system.fault", "failure", map[string]string{"fault": kind}, groups...)
}

func clock(condition string) func(*Event, []string) {
	apply := set("clock.sync", "failure", map[string]string{"clock.condition": condition})
	return func(e *Event, m []string) {
		apply(e, m)
		// The first submatch, if any, is an offset in seconds.
		if len(m) > 1 {
			if seconds, err := strconv.ParseFloat(m[1], 64); err == nil && math.Abs(seconds) < 1e9 {
				e.Fields["clock.offset_ms"] = strconv.FormatInt(int64(math.Round(seconds*1000)), 10)
			}
		}
	}
}

func synchronised(condition string) func(*Event, []string) {
	return set("clock.sync", "success", map[string]string{"clock.condition": condition})
}

// fromInit applies only to a journal record from systemd itself. journald
// records each sender's process ID, so a program writing as "systemd" cannot
// claim another unit's run; a syslog file carries only the ID the sender wrote.
func fromInit(apply func(*Event, []string)) func(*Event, []string) {
	return func(e *Event, m []string) {
		if e.Fields["_PID"] == "1" {
			apply(e, m)
		}
	}
}

// task records a routine task's unit finishing its run.
func task(kind, tool string) func(*Event, []string) {
	return fromInit(set("task.completed", "success", map[string]string{"task": kind, "task.tool": tool}, "task.unit"))
}

// protection records a protection taking effect, named by its unit.
func protection(kind, mechanism string) func(*Event, []string) {
	return fromInit(set("protection.activated", "success", map[string]string{"protection": kind, "protection.mechanism": mechanism}, "protection.unit"))
}

func dns(reason string) func(*Event, []string) {
	return set("dns.failure", "failure", map[string]string{"dns.reason": reason})
}

func account(change string, groups ...string) func(*Event, []string) {
	return set("account.change", "success", map[string]string{"account.change": change}, groups...)
}

func failedSignIn(service string, groups ...string) func(*Event, []string) {
	return set("authentication.failed", "failure", map[string]string{"auth.service": service, "auth.method": "password"}, groups...)
}

var phpLevels = map[string]string{"Fatal error": "fatal", "Parse error": "parse", "Recoverable fatal error": "recoverable", "Catchable fatal error": "recoverable"}

var phpError = regexp.MustCompile(`PHP (Fatal error|Parse error|Recoverable fatal error|Catchable fatal error):`)

func phpFailure(e *Event, m []string) {
	set("application.error", "failure", map[string]string{"app.name": "php", "app.level": phpLevels[m[1]], "app.category": "php"})(e, m)
}

func sudoDenied(e *Event, m []string) {
	set("access.denied", "failure", map[string]string{"access.type": "sudo", "access.executable": path.Base(m[2])}, "user.name")(e, m)
}

// fail2banBan records a ban by its jail; the banned address is not sent.
var fail2banBan = set("security.alert", "info", map[string]string{"alert.product": "fail2ban", "alert.category": "ban", "alert.level": "6", "alert.description": "Address banned"}, "alert.rule_id")

var hostRules = []hostRule{
	// Kernel faults.
	{"kernel", regexp.MustCompile(`Killed process \d+ \(([^)]{1,64})\)`), fault("oom_kill", "fault.process")},
	{"kernel", regexp.MustCompile(`(?:I/O error|critical medium error)[^\n]{0,64}?\bdev ([a-z0-9_-]{1,32})`), fault("io_error", "fault.device")},
	{"kernel", regexp.MustCompile(`(?:EXT4-fs error|BTRFS error) \(device ([a-z0-9_-]{1,32})\)|XFS \(([a-z0-9_-]{1,32})\): (?:Corruption|metadata I/O error|Filesystem has been shut down)`), fault("filesystem_error", "fault.device", "fault.device")},
	{"kernel", regexp.MustCompile(`(\S{1,64})\[\d+\]: segfault at `), fault("segfault", "fault.process")},
	{"kernel", regexp.MustCompile(`task (\S{1,64}):\d+ blocked for more than \d+ seconds`), fault("hung_task", "fault.process")},
	{"kernel", regexp.MustCompile(`Kernel panic|kernel BUG at|BUG: |Oops: |general protection fault`), fault("kernel_error")},
	{"kernel", regexp.MustCompile(`\[Hardware Error\]|Machine check events logged|EDAC \S{1,32}: \d+ (?:CE|UE) `), fault("hardware_error")},
	{"kernel audit", regexp.MustCompile(`apparmor="DENIED" operation="[^"]{1,64}"[^\n]*? comm="([^"]{1,64})"`), set("access.denied", "failure", map[string]string{"access.type": "APPARMOR"}, "access.executable")},
	{"kernel audit auditd", regexp.MustCompile(`avc:\s+denied\s+\{[^}]{1,128}\}[^\n]*? comm="([^"]{1,64})"`), set("access.denied", "failure", map[string]string{"access.type": "AVC"}, "access.executable")},
	// Services, crashes and capacity.
	{"systemd init", regexp.MustCompile(`^(\S{1,256}\.(?:service|socket|mount|timer|path|swap)): Failed with result '([^']{1,64})'`), fault("service_failed", "fault.unit", "fault.result")},
	{"systemd init", regexp.MustCompile(`^Unit (\S{1,256}) entered failed state\.`), fault("service_failed", "fault.unit")},
	{"systemd-coredump", regexp.MustCompile(`^Process \d+ \(([^)]{1,64})\) of user \d+ dumped core`), fault("core_dump", "fault.process")},
	{"", regexp.MustCompile(`server reached (?:pm\.)?max_children setting`), fault("worker_limit")},
	{"", regexp.MustCompile(`No space left on device`), fault("disk_full")},
	// Routine tasks and protections: systemd reports a unit's start job
	// finishing as "Finished <unit> - <description>." once the run succeeds
	// (systemd 257 on Debian 13; StatusUnitFormat=description omits the unit).
	{"systemd init", regexp.MustCompile(`^Finished (apt-daily-upgrade\.service) - `), task("patching", "apt")},
	{"systemd init", regexp.MustCompile(`^Finished (apparmor\.service) - `), protection("mandatory_access_control", "apparmor")},
	// Clock synchronisation.
	{"chronyd chrony", regexp.MustCompile(`^Selected source \S`), synchronised("source_selected")},
	{"systemd-timesyncd", regexp.MustCompile(`^Contacted time server \S`), synchronised("server_contacted")},
	{"systemd-timesyncd", regexp.MustCompile(`^Initial clock synchronization to `), synchronised("synchronised")},
	{"chronyd chrony", regexp.MustCompile(`Can't synchronise: no selectable sources|No suitable source for synchronisation`), clock("no_sources")},
	{"chronyd chrony", regexp.MustCompile(`System clock wrong by (-?\d{1,12}(?:\.\d{1,9})?) seconds`), clock("offset")},
	{"chronyd chrony", regexp.MustCompile(`System clock was stepped by (-?\d{1,12}(?:\.\d{1,9})?) seconds|Forward time jump detected`), clock("stepped")},
	{"ntpd", regexp.MustCompile(`no servers can be used|no servers reachable|no reply received`), clock("no_sources")},
	{"ntpd", regexp.MustCompile(`kernel reports TIME_ERROR|clock is now unsynced`), clock("unsynchronised")},
	{"ntpd", regexp.MustCompile(`frequency error -?\d{1,9} PPM exceeds tolerance`), clock("frequency")},
	{"ntpd", regexp.MustCompile(`spike_detect ([-+]?\d{1,12}(?:\.\d{1,9})?) s`), clock("jitter")},
	// ntpsec's ntpd and ntpdate write "CLOCK: time stepped by 0.318974".
	{"ntpd ntpdate", regexp.MustCompile(`(?:clock_step|time reset|time stepped by) ([-+]?\d{1,12}(?:\.\d{1,9})?)(?: s)?`), clock("stepped")},
	{"systemd-timesyncd", regexp.MustCompile(`Timed out waiting for reply from`), clock("source_unreachable")},
	// Name resolution.
	{"systemd-resolved", regexp.MustCompile(`Using degraded feature set`), dns("degraded")},
	{"systemd-resolved", regexp.MustCompile(`DNSSEC validation failed`), dns("dnssec_failed")},
	{"", regexp.MustCompile(`Temporary failure in name resolution`), dns("temporary_failure")},
	{"", regexp.MustCompile(`Could not resolve host|getaddrinfo(?:\(\))? failed|php_network_getaddresses`), dns("unresolved")},
	// Accounts and groups.
	{"useradd", regexp.MustCompile(`^new user: name=([^,\s]{1,64}),`), account("created", "user.name")},
	{"userdel", regexp.MustCompile(`^delete user '([^']{1,64})'`), account("deleted", "user.name")},
	{"usermod", regexp.MustCompile(`^change user '([^']{1,64})' password`), account("password_changed", "user.name")},
	{"usermod", regexp.MustCompile(`^add '([^']{1,64})' to group '([^']{1,64})'`), account("group_added", "user.name", "account.group")},
	{"usermod", regexp.MustCompile(`^delete '([^']{1,64})' from group '([^']{1,64})'`), account("group_removed", "user.name", "account.group")},
	{"usermod", regexp.MustCompile(`^lock user '([^']{1,64})' password`), account("locked", "user.name")},
	{"usermod", regexp.MustCompile(`^unlock user '([^']{1,64})' password`), account("unlocked", "user.name")},
	// useradd logs a new account's own group the same way, under the person's
	// login name; its "new user" line already records the account as a subject.
	{"groupadd", regexp.MustCompile(`^new group: name=([^,\s]{1,64}),`), account("group_created", "account.group")},
	{"groupdel", regexp.MustCompile(`^group '([^']{1,64})' removed$`), account("group_deleted", "account.group")},
	{"gpasswd", regexp.MustCompile(`^user (\S{1,64}) added by \S{1,64} to group (\S{1,64})`), account("group_added", "user.name", "account.group")},
	{"gpasswd", regexp.MustCompile(`^user (\S{1,64}) removed by \S{1,64} from group (\S{1,64})`), account("group_removed", "user.name", "account.group")},
	{"passwd chpasswd", regexp.MustCompile(`pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for (\S{1,64})`), account("password_changed", "user.name")},
	// Failed sign-ins and switching user.
	{"su", regexp.MustCompile(`pam_unix\(su(?:-l)?:auth\): authentication failure;(?:[^\n]*\bruser=(\S{1,64}))?`), failedSignIn("su", "user.name")},
	{"su", regexp.MustCompile(`pam_unix\(su(?:-l)?:session\): session opened for user \S{1,64} by (\w[^\s(]{0,63})`), set("privilege.switch", "success", map[string]string{"auth.service": "su"}, "user.name")},
	{"sudo", regexp.MustCompile(`^\s*(\S{1,64}) : \d+ incorrect password attempts? ;`), failedSignIn("sudo", "user.name")},
	{"sudo", regexp.MustCompile(`^\s*(\S{1,64}) : (?:user NOT in sudoers|command not allowed|user NOT authorized on host) ;[^\n]*COMMAND=(\S{1,1000})`), sudoDenied},
	{"login", regexp.MustCompile(`^FAILED LOGIN \(\d+\) on '[^']{0,64}' FOR '([^']{1,64})'`), failedSignIn("login", "user.name")},
	// Intrusion prevention.
	{"fail2ban-server fail2ban", regexp.MustCompile(`^(?:NOTICE\s+)?\[([A-Za-z0-9_.-]{1,64})\] Ban \S`), fail2banBan},
	{"", regexp.MustCompile(`fail2ban\.actions\s*\[\d+\]:\s*NOTICE\s+\[([A-Za-z0-9_.-]{1,64})\] Ban \S`), fail2banBan},
	// Applications.
	{"", phpError, phpFailure},
}

// Drupal's syslog module writes base_url|timestamp|type|ip|request_uri|referer|uid|link|message.
var drupalEntry = regexp.MustCompile(`^https?://[^|\s]{1,256}\|\d{9,11}\|([^|]{1,64})\|[^|]*\|[^|]*\|[^|]*\|\d{1,10}\|[^|]*\|(.*)$`)

var (
	drupalOpened   = regexp.MustCompile(`^Session opened for (.{1,64})\.$`)
	drupalFailed   = regexp.MustCompile(`^Login attempt failed (?:for (.{1,64})|from \S{1,64})\.$`)
	drupalAccount  = regexp.MustCompile(`^(New|Deleted|Blocked) user: (.{1,64}?)(?: \S{1,256}@\S{1,256})?\.$`)
	drupalPHPError = regexp.MustCompile(`^(?:Recoverable fatal error|Fatal error|[\w\\]{0,256}(?:Exception|Error|Wrapper)):`)
	priorityNames  = []string{"emergency", "alert", "critical", "error"}
	drupalChanges  = map[string]string{"New": "created", "Deleted": "deleted", "Blocked": "blocked"}
)

// drupal recognises sign-ins, account changes and errors in a watchdog entry.
func drupal(e *Event, message string) bool {
	m := drupalEntry.FindStringSubmatch(message)
	if m == nil {
		return false
	}
	kind, text := m[1], m[2]
	if kind == "user" {
		if u := drupalOpened.FindStringSubmatch(text); u != nil {
			set("authentication.accepted", "success", map[string]string{"auth.service": "drupal", "auth.method": "password"}, "user.name")(e, u)
			return true
		}
		if u := drupalFailed.FindStringSubmatch(text); u != nil {
			failedSignIn("drupal", "user.name")(e, u)
			return true
		}
		if u := drupalAccount.FindStringSubmatch(text); u != nil {
			account(drupalChanges[u[1]], "", "user.name")(e, u)
			e.Fields["account.tool"] = "drupal"
			return true
		}
	}
	level := ""
	if p, err := strconv.Atoi(e.Fields["log.syslog.priority"]); err == nil && p >= 0 && p < len(priorityNames) {
		level = priorityNames[p]
	} else if kind == "php" && drupalPHPError.MatchString(text) {
		level = "error"
	}
	if level == "" {
		return false
	}
	set("application.error", "failure", map[string]string{"app.name": "drupal", "app.level": level, "app.category": kind})(e, nil)
	return true
}

// classifyHost applies the first rule that recognises a message.
func classifyHost(e *Event, program, message string) {
	if drupal(e, message) {
		return
	}
	for _, rule := range hostRules {
		if rule.programs != "" && !strings.Contains(" "+rule.programs+" ", " "+program+" ") {
			continue
		}
		if m := rule.pattern.FindStringSubmatch(message); m != nil {
			rule.apply(e, m)
			return
		}
	}
}

// hostEvent turns a recognised message into its catalogue event.
func hostEvent(e Event) *recognised {
	f := e.Fields
	program := f["process.name"]
	if program == "" {
		program = "system"
	}
	attributes := func(pairs ...string) map[string]string {
		out := map[string]string{}
		for i := 0; i+1 < len(pairs); i += 2 {
			out[pairs[i]] = f[pairs[i+1]]
		}
		return out
	}
	r := func(eventType, action string, attrs map[string]string, subject bool) *recognised {
		out := &recognised{eventType, program, action, attrs, "", ""}
		if subject && f["user.name"] != "" {
			out.subjectKind, out.subject = "unix_user", f["user.name"]
			if f["auth.service"] == "drupal" || f["account.tool"] == "drupal" {
				out.subjectKind = "drupal_user"
			}
		}
		return out
	}
	switch e.Action {
	case "system.fault":
		a := attributes("fault", "fault", "process", "fault.process", "device", "fault.device", "unit", "fault.unit", "result", "fault.result")
		a["component"] = program
		return r("system.fault.detected", "detect", a, false)
	case "clock.sync":
		a := attributes("condition", "clock.condition", "offset_ms", "clock.offset_ms")
		a["daemon"] = program
		return r("clock.sync.changed", "synchronise", a, false)
	case "task.completed":
		return r("routine.task.completed", "complete", attributes("task", "task", "tool", "task.tool", "unit", "task.unit"), false)
	case "protection.activated":
		return r("system.protection.activated", "activate", attributes("protection", "protection", "mechanism", "protection.mechanism", "unit", "protection.unit"), false)
	case "dns.failure":
		a := attributes("reason", "dns.reason")
		a["process"] = program
		return r("dns.lookup.failed", "resolve", a, false)
	case "application.error":
		return r("application.error.logged", "log", attributes("application", "app.name", "level", "app.level", "category", "app.category"), false)
	case "account.change":
		a := attributes("change", "account.change", "group", "account.group", "tool", "account.tool")
		if a["tool"] == "" {
			a["tool"] = program
		}
		return r("user.account.changed", "change", a, true)
	case "authentication.accepted", "authentication.failed":
		if f["auth.service"] == "" {
			return nil
		}
		return r("user.authenticated", "authenticate", attributes("service", "auth.service", "method", "auth.method"), true)
	case "privilege.switch":
		return r("privileged.action.completed", "execute", map[string]string{"mechanism": f["auth.service"], "executable": f["auth.service"]}, true)
	case "access.denied":
		return r("access.denied", "deny", attributes("audit_type", "access.type", "executable", "access.executable"), true)
	case "security.alert":
		return r("security.alert.generated", "alert", attributes("product", "alert.product", "rule_id", "alert.rule_id", "level", "alert.level", "category", "alert.category", "description", "alert.description"), false)
	}
	return nil
}
