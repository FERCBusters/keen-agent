package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keen-agent/internal/ueu"
)

var november = ueu.CatalogueRef{ID: "keen", Version: "2026.11"}

// grantedSealer follows the catalogue KEEN granted.
func grantedSealer(t *testing.T, mode string, granted ueu.CatalogueRef) *sealer {
	t.Helper()
	id := testIdentity(t, "https://keen.example/api/v1/otlp/logs")
	id.Catalogue = granted
	z, err := newSealer(Config{EvidenceMode: mode}, id)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func TestHostMessagesBecomeCatalogueEvents(t *testing.T) {
	z := grantedSealer(t, "events", november)
	drupal := "Jan  1 00:00:00 web drupal: https://example.org|1767225600|"
	for _, tc := range []struct {
		name, parser, line, eventType, outcome string
		attributes                             map[string]any
		subject                                bool
	}{
		{"oom", "syslog", "Jan  1 00:00:00 web kernel: [12.3] Out of memory: Killed process 4242 (php-fpm8.2) total-vm:1024kB", "system.fault.detected", "failure", map[string]any{"component": "kernel", "fault": "oom_kill", "process": "php-fpm8.2"}, false},
		{"io", "syslog", "Jan  1 00:00:00 web kernel: [1.0] blk_update_request: I/O error, dev sda, sector 2048 op 0x0:(READ)", "system.fault.detected", "failure", map[string]any{"fault": "io_error", "device": "sda"}, false},
		{"xfs", "syslog", "Jan  1 00:00:00 web kernel: [1.0] XFS (dm-0): Corruption detected. Unmount and run xfs_repair", "system.fault.detected", "failure", map[string]any{"fault": "filesystem_error", "device": "dm-0"}, false},
		{"unit", "syslog", "Jan  1 00:00:00 web systemd[1]: nginx.service: Failed with result 'exit-code'.", "system.fault.detected", "failure", map[string]any{"component": "systemd", "fault": "service_failed", "unit": "nginx.service", "result": "exit-code"}, false},
		{"disk-full", "syslog", "Jan  1 00:00:00 web postgres[77]: could not write to file \"base/pgsql_tmp\": No space left on device", "system.fault.detected", "failure", map[string]any{"component": "postgres", "fault": "disk_full"}, false},
		{"workers", "syslog", "Jan  1 00:00:00 web php-fpm8.2[900]: [WARNING] [pool www] server reached pm.max_children setting (5), consider raising it", "system.fault.detected", "failure", map[string]any{"fault": "worker_limit"}, false},
		{"chrony", "syslog", "Jan  1 00:00:00 web chronyd[500]: System clock wrong by -1.234567 seconds", "clock.sync.changed", "failure", map[string]any{"daemon": "chronyd", "condition": "offset", "offset_ms": int64(-1235)}, false},
		{"chrony-stepped", "syslog", "Jan  1 00:00:00 web chronyd[500]: System clock was stepped by 1.456789 seconds", "clock.sync.changed", "failure", map[string]any{"condition": "stepped", "offset_ms": int64(1457)}, false},
		{"chrony-selected", "syslog", "Jan  1 00:00:00 web chronyd[500]: Selected source 192.0.2.1 (ntp.example)", "clock.sync.changed", "success", map[string]any{"daemon": "chronyd", "condition": "source_selected"}, false},
		{"chrony-selected-v6", "syslog", "Jan  1 00:00:00 web chronyd[500]: Selected source 2001:db8::123 (ntp.example)", "clock.sync.changed", "success", map[string]any{"condition": "source_selected"}, false},
		{"timesyncd-contacted", "syslog", "Jan  1 00:00:00 web systemd-timesyncd[400]: Contacted time server 192.0.2.1:123 (ntp.example).", "clock.sync.changed", "success", map[string]any{"daemon": "systemd-timesyncd", "condition": "server_contacted"}, false},
		{"timesyncd-initial", "syslog", "Jan  1 00:00:00 web systemd-timesyncd[400]: Initial clock synchronization to Thu 2026-01-01 00:00:00.123456 UTC.", "clock.sync.changed", "success", map[string]any{"condition": "synchronised"}, false},
		{"ntpsec-unsynchronised", "syslog", "Jan  1 00:00:00 web ntpd[600]: CLOCK: kernel reports TIME_ERROR: 0x41: Clock Unsynchronized", "clock.sync.changed", "failure", map[string]any{"daemon": "ntpd", "condition": "unsynchronised"}, false},
		{"ntpdate-stepped", "syslog", "Jan  1 00:00:00 web ntpdate[700]: CLOCK: time stepped by 0.425731", "clock.sync.changed", "failure", map[string]any{"daemon": "ntpdate", "condition": "stepped", "offset_ms": int64(426)}, false},
		{"jitter", "syslog", "Jan  1 00:00:00 web ntpd[600]: 0.0.0.0 0617 07 spike_detect +0.523217 s", "clock.sync.changed", "failure", map[string]any{"daemon": "ntpd", "condition": "jitter", "offset_ms": int64(523)}, false},
		{"resolved", "syslog", "Jan  1 00:00:00 web systemd-resolved[300]: Using degraded feature set UDP instead of UDP+EDNS0 for DNS server 192.0.2.53.", "dns.lookup.failed", "failure", map[string]any{"process": "systemd-resolved", "reason": "degraded"}, false},
		{"curl", "syslog", "Jan  1 00:00:00 web backup.sh[800]: curl: (6) Could not resolve host: backups.internal", "dns.lookup.failed", "failure", map[string]any{"process": "backup.sh", "reason": "unresolved"}, false},
		{"php-fpm", "syslog", `Jan  1 00:00:00 web php-fpm8.2[900]: [WARNING] [pool www] child 901 said into stderr: "PHP Fatal error:  Uncaught Error: Call to undefined function x() in /var/www/secret.php:3"`, "application.error.logged", "failure", map[string]any{"application": "php", "level": "fatal", "category": "php"}, false},
		{"php-log", "php", "[01-Jan-2026 00:00:00 UTC] PHP Parse error:  syntax error, unexpected end of file in /var/www/secret.php on line 9", "application.error.logged", "failure", map[string]any{"application": "php", "level": "parse"}, false},
		{"drupal-login", "syslog", drupal + "user|192.0.2.9|https://example.org/user/login|https://example.org/|0||Login attempt failed for alice.", "user.authenticated", "failure", map[string]any{"service": "drupal", "method": "password"}, true},
		{"drupal-session", "syslog", drupal + "user|192.0.2.9|https://example.org/user/login|https://example.org/|7||Session opened for alice.", "user.authenticated", "success", map[string]any{"service": "drupal"}, true},
		{"drupal-account", "syslog", drupal + "user|192.0.2.9|https://example.org/admin|https://example.org/|1||New user: alice alice@example.org.", "user.account.changed", "success", map[string]any{"tool": "drupal", "change": "created"}, true},
		{"drupal-php", "syslog", drupal + "php|192.0.2.9|https://example.org/node/1||5||TypeError: Argument 1 passed to x() must be an array in /var/www/secret.php", "application.error.logged", "failure", map[string]any{"application": "drupal", "level": "error", "category": "php"}, false},
		{"useradd", "syslog", "Jan  1 00:00:00 web useradd[1000]: new user: name=alice, UID=1001, GID=1001, home=/home/alice, shell=/bin/bash, from=/dev/pts/0", "user.account.changed", "success", map[string]any{"tool": "useradd", "change": "created"}, true},
		{"usermod", "syslog", "Jan  1 00:00:00 web usermod[1001]: add 'alice' to group 'sudo'", "user.account.changed", "success", map[string]any{"change": "group_added", "group": "sudo"}, true},
		{"groupadd", "syslog", "Jan  1 00:00:00 web groupadd[1002]: new group: name=deploy, GID=1002", "user.account.changed", "success", map[string]any{"change": "group_created", "group": "deploy"}, false},
		{"sudo-password", "syslog", "Jan  1 00:00:00 web sudo[7]:    alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update", "user.authenticated", "failure", map[string]any{"service": "sudo", "method": "password"}, true},
		{"sudo-refused", "syslog", "Jan  1 00:00:00 web sudo[7]:    alice : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update", "access.denied", "failure", map[string]any{"audit_type": "sudo", "executable": "apt"}, true},
		{"su-failed", "syslog", "Jan  1 00:00:00 web su[50]: pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=root", "user.authenticated", "failure", map[string]any{"service": "su"}, true},
		{"su", "syslog", "Jan  1 00:00:00 web su[51]: pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)", "privileged.action.completed", "success", map[string]any{"mechanism": "su", "executable": "su"}, true},
		{"login", "syslog", "Jan  1 00:00:00 web login[52]: FAILED LOGIN (1) on '/dev/tty1' FOR 'alice', Authentication failure", "user.authenticated", "failure", map[string]any{"service": "login"}, true},
		{"apparmor", "syslog", `Jan  1 00:00:00 web kernel: [1.0] audit: type=1400 audit(1.0:2): apparmor="DENIED" operation="open" profile="/usr/sbin/nginx" name="/etc/shadow" pid=12 comm="nginx" requested_mask="r"`, "access.denied", "failure", map[string]any{"audit_type": "APPARMOR", "executable": "nginx"}, false},
		{"selinux", "auditd", `type=AVC msg=audit(1791240000.001:12): avc:  denied  { read } for  pid=12 comm="httpd" name="shadow" scontext=system_u:system_r:httpd_t:s0 tclass=file permissive=0`, "access.denied", "failure", map[string]any{"audit_type": "AVC", "executable": "httpd"}, false},
		{"fail2ban", "syslog", "2026-01-01 00:00:00,123 fail2ban.actions        [1234]: NOTICE  [sshd] Ban 192.0.2.7", "security.alert.generated", "info", map[string]any{"product": "fail2ban", "rule_id": "sshd", "level": int64(6), "category": "ban"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envs := classify(t, z, Source{Name: tc.name, Parser: tc.parser}, tc.line)
			if len(envs) != 1 || envs[0]["event_type"] != tc.eventType {
				t.Fatalf("%v", envs)
			}
			if got := envs[0]["event"].(map[string]any)["outcome"]; got != tc.outcome {
				t.Fatalf("outcome %v", got)
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
			// Names, addresses, hosts and paths stay on the host.
			text := canonical(t, envs[0])
			for _, secret := range []string{"alice", "192.0.2", "2001:db8", "ntp.example", "backups.internal", "secret.php", "/etc/shadow"} {
				if strings.Contains(text, secret) {
					t.Fatalf("%q disclosed: %s", secret, text)
				}
			}
		})
	}
	// Ordinary messages, the copies shadow tools log for the shadow files, the
	// groups useradd and userdel create and remove with an account, other units
	// finishing,
	// unit results in a syslog file, where the sender writes its own process ID,
	// and Drupal entries that are neither errors nor sign-ins are not evidence.
	for _, line := range []string{
		"Jan  1 00:00:00 web systemd[1]: Started nginx.service - A high performance web server.",
		"Jan  1 00:00:00 web systemd[1]: Finished apt-daily.service - Daily apt download activities.",
		"Jan  1 00:00:00 web systemd[1]: apt-daily-upgrade.service: Deactivated successfully.",
		"Jan  1 00:00:00 web systemd[1]: Finished apt-daily-upgrade.service - Daily apt upgrade and clean activities.",
		"Jan  1 00:00:00 web systemd[1]: Finished apparmor.service - Load AppArmor profiles.",
		"Jan  1 00:00:00 web useradd[1000]: new group: name=alice, GID=1001",
		"Jan  1 00:00:00 web chronyd[500]: Source 192.0.2.1 replaced with 192.0.2.2 (ntp.example)",
		"Jan  1 00:00:00 web systemd-timesyncd[400]: Network configuration changed, trying to establish connection.",
		"Jan  1 00:00:00 web ntpdate[700]: 2026-01-01 00:00:00.123456 (+0000) +0.425731 +/- 0.003125 ntp.example 192.0.2.1 s1 no-leap",
		"Jan  1 00:00:00 web usermod[1001]: add 'alice' to shadow group 'sudo'",
		"Jan  1 00:00:00 web groupadd[1002]: group added to /etc/group: name=deploy, GID=1002",
		"Jan  1 00:00:00 web kernel: [0.1] EDAC MC: Ver: 3.0.0",
		"Jan  1 00:00:00 web userdel[1003]: delete 'alice' from group 'sudo'",
		"Jan  1 00:00:00 web userdel[1003]: removed group 'alice' owned by 'alice'",
		"Jan  1 00:00:00 web fake[5]: [sshd] Ban 192.0.2.7",
		drupal + "content|192.0.2.9|https://example.org/node/add||1||article: added Hello.",
		drupal + "php|192.0.2.9|https://example.org/node/1||5||Warning: Undefined variable $x in y()",
	} {
		if envs := classify(t, z, Source{Name: "syslog", Parser: "syslog"}, line); len(envs) != 0 {
			t.Fatalf("%q became %v", line, envs)
		}
	}
}

func TestJournalErrorsUseTheirPriority(t *testing.T) {
	z := grantedSealer(t, "events", november)
	e := parse(Config{}, Source{Name: "journal", Kind: "journal", Parser: "syslog"}, "https://example.org|1767225600|cron|192.0.2.9|https://example.org/cron||0||Cron run failed.", time.Now())
	e.Fields["SYSLOG_IDENTIFIER"], e.Fields["PRIORITY"] = "drupal", "3"
	normalizeJournal(&e)
	envs, err := z.envelopes(Source{Name: "journal", Kind: "journal", Parser: "syslog"}, e)
	if err != nil || len(envs) != 1 {
		t.Fatal(envs, err)
	}
	if got := envs[0]["attributes"].(map[string]any); got["application"] != "drupal" || got["level"] != "error" || got["category"] != "cron" {
		t.Fatal(got)
	}
}

func TestUnitResultsComeFromSystemdItself(t *testing.T) {
	z := grantedSealer(t, "events", november)
	source := Source{Name: "journal", Kind: "journal", Parser: "syslog"}
	finished := func(message, pid, uid string) []map[string]any {
		e := parse(Config{}, source, message, time.Now())
		e.Fields["SYSLOG_IDENTIFIER"], e.Fields["_PID"], e.Fields["_UID"], e.Fields["_COMM"] = "systemd", pid, uid, "systemd"
		normalizeJournal(&e)
		envs, err := z.envelopes(source, e)
		if err != nil {
			t.Fatal(err)
		}
		return envs
	}
	for _, tc := range []struct {
		message, eventType string
		attributes         map[string]any
	}{
		// systemd 257 names the unit before its description; systemd 249 logs the description alone.
		{"Finished apt-daily-upgrade.service - Daily apt upgrade and clean activities.", "routine.task.completed", map[string]any{"task": "patching", "tool": "apt", "unit": "apt-daily-upgrade.service"}},
		{"Finished Daily apt upgrade and clean activities.", "routine.task.completed", map[string]any{"task": "patching", "unit": "apt-daily-upgrade.service"}},
		{"Finished certbot.service - Certbot.", "routine.task.completed", map[string]any{"task": "certificate_renewal", "tool": "certbot", "unit": "certbot.service"}},
		{"Finished Certbot.", "routine.task.completed", map[string]any{"task": "certificate_renewal", "unit": "certbot.service"}},
		{"Finished apparmor.service - Load AppArmor profiles.", "system.protection.activated", map[string]any{"protection": "mandatory_access_control", "mechanism": "apparmor", "unit": "apparmor.service"}},
		{"Finished Load AppArmor profiles.", "system.protection.activated", map[string]any{"mechanism": "apparmor", "unit": "apparmor.service"}},
	} {
		envs := finished(tc.message, "1", "0")
		if len(envs) != 1 || envs[0]["event_type"] != tc.eventType || envs[0]["event"].(map[string]any)["outcome"] != "success" {
			t.Fatal(envs)
		}
		got := envs[0]["attributes"].(map[string]any)
		for k, v := range tc.attributes {
			if got[k] != v {
				t.Fatalf("%s=%v, want %v", k, got[k], v)
			}
		}
		if _, ok := envs[0]["subject"]; ok {
			t.Fatal("subject sent")
		}
		// journald records the sender's process ID itself, so an account writing
		// the same text as "systemd" (logger -t systemd) does not produce the event.
		if envs := finished(tc.message, "4242", "1000"); len(envs) != 0 {
			t.Fatal(envs)
		}
	}
	// ufw's unit finishes when ufw is disabled too, and other units, a unit's
	// deactivation and a failed start are not completed runs.
	for _, message := range []string{
		"Finished Uncomplicated firewall.",
		"Finished ufw.service - Uncomplicated firewall.",
		"Finished apt-daily.service - Daily apt download activities.",
		"Finished Certbot renewal.",
		"apt-daily-upgrade.service: Deactivated successfully.",
		"Failed to start certbot.service - Certbot.",
	} {
		if envs := finished(message, "1", "0"); len(envs) != 0 {
			t.Fatalf("%q became %v", message, envs)
		}
	}
}

func TestRootShellCommandsArePrivilegedActions(t *testing.T) {
	// Programs installed in the system directories, for this test.
	bin := t.TempDir()
	for _, name := range []string{"vim.tiny", "git", "deploy-app", "curl", "grep", "mysql", "make"} {
		if err := os.WriteFile(filepath.Join(bin, name), nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "notes.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	saved := commandDirs
	t.Cleanup(func() { commandDirs = saved })
	commandDirs = []string{bin}

	z := grantedSealer(t, "events", november)
	source := Source{Name: "journal", Kind: "journal", Parser: "syslog"}
	logged := func(tag, uid, transport, status, command string) []map[string]any {
		e := parse(Config{}, source, "shell user [4242]: Executing command [CWD=/srv/secret-project ; "+status+"]: "+command, time.Now())
		e.Fields["SYSLOG_IDENTIFIER"], e.Fields["_UID"], e.Fields["_PID"], e.Fields["_TRANSPORT"] = tag, uid, "4243", transport
		normalizeJournal(&e)
		envs, err := z.envelopes(source, e)
		if err != nil {
			t.Fatal(err)
		}
		return envs
	}
	for _, tc := range []struct{ status, command, executable string }{
		{"0", "vim.tiny notes.txt", "vim.tiny"},
		{"141", `\git log`, "git"},
		{"0", bin + "/deploy-app", "deploy-app"},
		{"0", "grep 'No space left on device' /var/log/syslog", "grep"},
		{"0", "make\nmake install", "make"},
		// Typed text that names no installed program stays on the host.
		{"0", "cd /srv/secret-project/", ""},
		{"0", "notes.txt", ""},
		{"0", "/home/alice/bin/make", ""},
		{"0", "./alice-fix-perms.sh", ""},
		{"0", "db01.corp.example.org", ""},
		{"127", "hunter2secret", ""},
		{"127", "git", ""},
		{"0", "TOKEN=hunter2secret curl https://example.org", ""},
		{"0", `MYSQL_PWD="correct horse" mysql`, ""},
		{"0", `X=a\ hunter2secret make`, ""},
		{"0", "X=a hunter2secret make", ""},
		{"0", " hunter2secret", ""},
		{"0", "(cd /srv/secret-project && make)", ""},
	} {
		envs := logged("root", "0", "syslog", tc.status, tc.command)
		if len(envs) != 1 || envs[0]["event_type"] != "privileged.action.completed" {
			t.Fatalf("%q: %v", tc.command, envs)
		}
		got := envs[0]["attributes"].(map[string]any)
		// An absent executable is left out of the envelope.
		if name, _ := got["executable"].(string); got["mechanism"] != "shell" || name != tc.executable {
			t.Fatalf("%q: %v", tc.command, got)
		}
		if _, ok := envs[0]["subject"]; !ok {
			t.Fatalf("%q: no subject", tc.command)
		}
		text := canonical(t, envs[0])
		for _, secret := range []string{"secret-project", "notes.txt", "hunter2", "horse", "alice", "example.org", "No space left", "/var/log/syslog"} {
			if strings.Contains(text, secret) {
				t.Fatalf("%q disclosed: %s", secret, text)
			}
		}
	}
	// journald records the sender's user ID and transport, so another
	// account's shell, that account writing as "root", and a root daemon
	// relaying a container's or service's output are not privileged actions;
	// neither is their command line taken for a fault.
	for _, sender := range [][3]string{{"miguel", "1001", "syslog"}, {"root", "1001", "syslog"}, {"web", "0", "journal"}, {"root", "0", "stdout"}} {
		for _, command := range []string{"sudo su", "grep 'No space left on device' /var/log/syslog"} {
			if envs := logged(sender[0], sender[1], sender[2], "0", command); len(envs) != 0 {
				t.Fatalf("%v %q: %v", sender, command, envs)
			}
		}
	}
	// A syslog file carries no sender ID.
	file := classify(t, z, Source{Name: "syslog", Parser: "syslog"}, "Jan  1 00:00:00 web root[5]: shell user [5]: Executing command [CWD=/root ; 0]: ls")
	if len(file) != 0 {
		t.Fatal(file)
	}
}

func TestNewEventTypesWaitForKEENsGrant(t *testing.T) {
	oom := "Jan  1 00:00:00 web kernel: [12.3] Out of memory: Killed process 4242 (php-fpm8.2) total-vm:1024kB"
	sudo := "Jan  1 00:00:00 web sudo[7]:    alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"
	source := Source{Name: "system", Parser: "syslog"}

	// A KEEN that granted no newer catalogue receives only event types it knows.
	older := grantedSealer(t, "events", ueu.CatalogueRef{})
	if older.producer.Catalogue.Ref.Version != "2026.10" {
		t.Fatal(older.producer.Catalogue.Ref)
	}
	if envs := classify(t, older, source, oom); len(envs) != 0 {
		t.Fatal(envs)
	}
	if envs := classify(t, older, source, sudo); len(envs) != 1 || envs[0]["event_type"] != "user.authenticated" {
		t.Fatal(envs)
	}
	// In all_lines mode the message is still sent, as a line with its fields.
	envs := classify(t, grantedSealer(t, "all_lines", ueu.CatalogueRef{}), source, oom)
	if len(envs) != 1 || envs[0]["event_type"] != "log.line.collected" {
		t.Fatal(envs)
	}
	if got := envs[0]["attributes"].(map[string]any); got["fault"] != "oom_kill" || got["fault.process"] != "php-fpm8.2" || got["action"] != "system.fault" {
		t.Fatal(got)
	}
	granted := grantedSealer(t, "events", november)
	if envs := classify(t, granted, source, oom); len(envs) != 1 || envs[0]["catalogue"].(map[string]any)["version"] != "2026.11" {
		t.Fatal(envs)
	}
}
