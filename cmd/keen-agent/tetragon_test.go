package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Captured from Tetragon 1.6 on Docker with the anomaly policies; the
// account's directory is renamed.
const (
	tetragonSudo         = `{"process_exec":{"process":{"exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzUyMDAwMDAwMDozNjcxNDc0","pid":3671474,"uid":0,"cwd":"/home/alice","binary":"/usr/bin/sudo","arguments":"su","flags":"procFS","start_time":"2026-11-24T23:14:05.166405165Z","auid":1001,"parent_exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzE5MDAwMDAwMDozNjcxNDU1","tid":3671474,"in_init_tree":false},"parent":{"exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzE5MDAwMDAwMDozNjcxNDU1","pid":3671455,"uid":1001,"cwd":"/home/alice","binary":"/usr/bin/bash","flags":"procFS","start_time":"2026-11-24T23:14:04.836405337Z","auid":1001,"parent_exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNjgyMDAwMDAwMDozNjcxNDI4","tid":3671455,"in_init_tree":false}},"node_name":"5461eb9a26a0","time":"2026-11-24T23:14:05.166404668Z"}`
	tetragonSudoChild    = `{"process_exec":{"process":{"exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzU1MDAwMDAwMDozNjcxNDc2","pid":3671476,"uid":0,"cwd":"/home/alice","binary":"/usr/bin/sudo","arguments":"su","flags":"procFS","start_time":"2026-11-24T23:14:05.196405189Z","auid":1001,"parent_exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzUyMDAwMDAwMDozNjcxNDc0","tid":3671476,"in_init_tree":false},"parent":{"exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzUyMDAwMDAwMDozNjcxNDc0","pid":3671474,"uid":0,"cwd":"/home/alice","binary":"/usr/bin/sudo","arguments":"su","flags":"procFS","start_time":"2026-11-24T23:14:05.166405165Z","auid":1001,"parent_exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzE5MDAwMDAwMDozNjcxNDU1","tid":3671474,"in_init_tree":false}},"node_name":"5461eb9a26a0","time":"2026-11-24T23:14:05.196404705Z"}`
	tetragonSuFromSudo   = `{"process_exec":{"process":{"exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzU1MDAwMDAwMDozNjcxNDc3","pid":3671477,"uid":0,"cwd":"/","binary":"/usr/bin/su","flags":"procFS","start_time":"2026-11-24T23:14:05.196405228Z","auid":1001,"parent_exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzU1MDAwMDAwMDozNjcxNDc2","tid":3671477,"in_init_tree":false},"parent":{"exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzU1MDAwMDAwMDozNjcxNDc2","pid":3671476,"uid":0,"cwd":"/home/alice","binary":"/usr/bin/sudo","arguments":"su","flags":"procFS","start_time":"2026-11-24T23:14:05.196405189Z","auid":1001,"parent_exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzUyMDAwMDAwMDozNjcxNDc0","tid":3671476,"in_init_tree":false}},"node_name":"5461eb9a26a0","time":"2026-11-24T23:14:05.196404653Z"}`
	tetragonShadowRead   = `{"process_kprobe":{"process":{"exec_id":"NTQ2MWViOWEyNmEwOjE5OTIzODEwNzA0MjgyMTo0MTA3MTE4","pid":4107118,"uid":0,"cwd":"/root","binary":"/usr/bin/cat","arguments":"/etc/shadow","flags":"execve clone","start_time":"2026-11-25T04:14:35.753449069Z","auid":1001,"parent_exec_id":"NTQ2MWViOWEyNmEwOjE5NDMxMjAwMDAwMDAwMDozOTk2NTEz","refcnt":1,"tid":4107118,"in_init_tree":false},"parent":{"exec_id":"NTQ2MWViOWEyNmEwOjE5NDMxMjAwMDAwMDAwMDozOTk2NTEz","pid":3996513,"uid":0,"cwd":"/root","binary":"/usr/bin/bash","flags":"procFS","start_time":"2026-11-25T02:52:29.646405183Z","auid":1001,"parent_exec_id":"NTQ2MWViOWEyNmEwOjE5NDMxMTk3MDAwMDAwMDozOTk2NTEx","tid":3996513,"in_init_tree":false},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/etc/shadow","permission":"-rw-r-----"}},{"int_arg":4}],"action":"KPROBE_ACTION_POST","policy_name":"anomaly-secret-reads","return_action":"KPROBE_ACTION_POST"},"node_name":"5461eb9a26a0","time":"2026-11-25T04:14:35.754538971Z"}`
	tetragonHomeKeyRead  = `{"process_kprobe":{"process":{"pid":7,"uid":1002,"binary":"/home/alice/bin/backup-tool","arguments":"--key /home/alice/.ssh/id_ed25519","auid":1002},"parent":{"pid":6,"uid":1002,"binary":"/usr/bin/bash"},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/home/alice/.ssh/id_ed25519"}},{"int_arg":4}],"action":"KPROBE_ACTION_POST","policy_name":"anomaly-secret-reads"},"node_name":"web","time":"2026-11-25T04:14:35Z"}`
	tetragonReverseShell = `{"process_kprobe":{"process":{"pid":9,"uid":33,"binary":"/usr/bin/bash","auid":4294967295,"docker":"0f3c2a9d81b7e4c"},"parent":{"pid":8,"uid":33,"binary":"/usr/sbin/php-fpm8.4"},"function_name":"tcp_connect","args":[{"sock_arg":{"family":"AF_INET","type":"SOCK_STREAM","protocol":"IPPROTO_TCP","saddr":"172.17.0.5","daddr":"203.0.113.9","sport":51544,"dport":4444}}],"action":"KPROBE_ACTION_POST","policy_name":"anomaly-shell-network-connections","message":"Shell connected out","tags":["reverse-shell","mitre:T1059"]},"node_name":"web","time":"2026-11-25T05:00:00Z"}`
)

func tetragonExecLine(binary, arguments string, uid int, parent string, parentUID int) string {
	return fmt.Sprintf(`{"process_exec":{"process":{"pid":20,"uid":%d,"binary":%q,"arguments":%q,"auid":1001},"parent":{"pid":19,"uid":%d,"binary":%q}},"node_name":"web","time":"2026-11-25T06:00:00Z"}`, uid, binary, arguments, parentUID, parent)
}

func tetragonPolicyLine(function, args string) string {
	return `{"process_kprobe":{"process":{"pid":30,"uid":0,"binary":"/usr/bin/tool","auid":1001},"parent":{"pid":29,"uid":0,"binary":"/usr/bin/bash"},"function_name":"` + function + `","args":` + args + `,"action":"KPROBE_ACTION_POST","policy_name":"custom-policy"},"node_name":"web","time":"2026-11-25T06:00:00Z"}`
}

func TestTetragonSecretReadIsASecurityAlert(t *testing.T) {
	e := parse(Config{}, Source{Name: "tetragon", Parser: "tetragon"}, tetragonShadowRead, time.Now())
	if e.Action != "file.read" || e.Severity != 8 || e.Actor != "1001" || e.Summary != "cat read /etc/shadow" || e.Timestamp.Format(time.RFC3339Nano) != "2026-11-25T04:14:35.754538971Z" {
		t.Fatal(e)
	}
	for k, v := range map[string]string{"tetragon.policy.name": "anomaly-secret-reads", "tetragon.function": "security_file_permission", "file.path": "/etc/shadow", "tetragon.file.mask": "4", "process.name": "cat", "process.parent.name": "bash", "process.user.id": "0", "tetragon.node.name": "5461eb9a26a0", "tetragon.event": "process_kprobe"} {
		if e.Fields[k] != v {
			t.Fatalf("%s=%q, want %q", k, e.Fields[k], v)
		}
	}
	z := sealerFor(t, "events", "events")
	envs := classify(t, z, Source{Name: "tetragon", Parser: "tetragon"}, tetragonShadowRead)
	if len(envs) != 1 || envs[0]["event_type"] != "security.alert.generated" {
		t.Fatal(envs)
	}
	got := envs[0]["attributes"].(map[string]any)
	want := map[string]any{"product": "tetragon", "rule_id": "anomaly-secret-reads", "level": int64(8), "category": "file.read", "description": "cat read /etc/shadow"}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s=%v (%T), want %v", k, got[k], got[k], v)
		}
	}
	if groups := fmt.Sprint(got["groups"]); groups != "[process_kprobe security_file_permission action:post]" {
		t.Fatal(groups)
	}
	if envs[0]["source"].(map[string]any)["component"] != "tetragon" || envs[0]["subject"] == nil {
		t.Fatal(envs[0])
	}
	text := canonical(t, envs[0])
	// Anchored on a quote, or long enough, that no digest or pseudonym can
	// contain them: any key ending in auid, any value starting /root.
	for _, private := range []string{`auid"`, `"/root`, "NTQ2MWViOWEy", "5461eb9a26a0"} {
		if strings.Contains(text, private) {
			t.Fatalf("%q sent in events mode: %s", private, text)
		}
	}
}

func TestTetragonSudoChainIsOnePrivilegedAction(t *testing.T) {
	z := sealerFor(t, "events", "events")
	s := Source{Name: "tetragon", Parser: "tetragon"}
	envs := classify(t, z, s, tetragonSudo)
	if len(envs) != 1 || envs[0]["event_type"] != "privileged.action.completed" || envs[0]["subject"] == nil {
		t.Fatal(envs)
	}
	got := envs[0]["attributes"].(map[string]any)
	if got["mechanism"] != "sudo" || got["executable"] != "su" || got["audit_type"] != "process_exec" || envs[0]["event"].(map[string]any)["outcome"] != "success" {
		t.Fatal(got)
	}
	for _, line := range []string{tetragonSudoChild, tetragonSuFromSudo} {
		if envs := classify(t, z, s, line); len(envs) != 0 {
			t.Fatalf("repeated escalation became evidence: %v", envs)
		}
		if e := parse(Config{}, s, line, time.Now()); e.Fields["tetragon.exec.kind"] != "privilege_child" {
			t.Fatal(e)
		}
	}
	// Without a login uid the invoking account is the subject.
	line := strings.Replace(tetragonSudo, `"auid":1001,"parent_exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNjgy`, `"parent_exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNjgy`, 1)
	line = strings.Replace(line, `"auid":1001,"parent_exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzE5`, `"auid":4294967295,"parent_exec_id":"NTQ2MWViOWEyNmEwOjE4MTIwNzE5`, 1)
	e := parse(Config{}, s, line, time.Now())
	if e.Actor != "1001" || e.Fields["tetragon.process.auid"] != "" || e.Summary != "bash gained root through sudo" {
		t.Fatal(e)
	}
	if r := recogniseTetragon(e); r == nil || r.subject != "1001" || r.subjectKind != "unix_uid" {
		t.Fatal(r)
	}
	// su run directly from a user's shell is the escalation itself.
	if envs := classify(t, z, s, tetragonExecLine("/usr/bin/su", "-", 0, "/usr/bin/bash", 1001)); len(envs) != 1 || envs[0]["attributes"].(map[string]any)["mechanism"] != "su" {
		t.Fatal(envs)
	}
	if _, named := envs[0]["attributes"].(map[string]any)["executable"]; !named {
		t.Fatal("sudo's command lost")
	}
}

func TestTetragonWatchedProgramStarts(t *testing.T) {
	z := sealerFor(t, "events", "events")
	s := Source{Name: "tetragon", Parser: "tetragon"}
	for _, tc := range []struct {
		line, category, groups, description string
		level                               int64
	}{
		{tetragonExecLine("/usr/bin/nc", "-l arg:4444", 1001, "/usr/bin/bash", 1001), "process.exec.watched", "[process_exec nc parent:bash]", "nc started by bash", 3},
		{tetragonExecLine("/bin/sh", "-c arg:id", 33, "/usr/sbin/nginx", 33), "process.exec.service_shell", "[process_exec sh parent:nginx]", "sh started by nginx", 9},
		{tetragonExecLine("/usr/bin/passwd", "arg:alice", 0, "/usr/bin/bash", 1001), "process.exec.watched", "[process_exec passwd parent:bash setuid]", "passwd started by bash", 3},
		{tetragonExecLine("/usr/bin/tcpdump", "-i arg:eth0", 0, "", 0), "process.exec.watched", "[process_exec tcpdump]", "tcpdump started by an unknown parent", 3},
	} {
		envs := classify(t, z, s, tc.line)
		if len(envs) != 1 || envs[0]["event_type"] != "security.alert.generated" {
			t.Fatal(envs)
		}
		got := envs[0]["attributes"].(map[string]any)
		if got["rule_id"] != "process_exec" || got["category"] != tc.category || got["level"] != tc.level || got["description"] != tc.description || fmt.Sprint(got["groups"]) != tc.groups {
			t.Fatal(got)
		}
		// Hex digests and base64 never contain a colon, and in JSON one after
		// a key follows a quote, so only the arguments can produce "arg:".
		if strings.Contains(canonical(t, envs[0]), "arg:") {
			t.Fatal("arguments sent in events mode")
		}
	}
}

func TestTetragonPolicyHooksAndDescriptions(t *testing.T) {
	s := Source{Name: "tetragon", Parser: "tetragon"}
	for _, tc := range []struct {
		line, category, description string
		severity                    int
	}{
		{tetragonPolicyLine("security_file_permission", `[{"file_arg":{"path":"/etc/sudoers"}},{"int_arg":2}]`), "file.write", "tool wrote to /etc/sudoers", 8},
		{tetragonPolicyLine("security_file_permission", `[{"file_arg":{"path":"/etc/passwd"}},{"int_arg":10}]`), "file.write", "tool wrote to /etc/passwd", 8},
		{tetragonPolicyLine("security_file_permission", `[{"file_arg":{"path":"/etc/passwd"}},{"int_arg":1}]`), "file.access", "tool accessed /etc/passwd", 6},
		{tetragonPolicyLine("security_file_open", `[{"file_arg":{"path":"/etc/hosts","flags":"O_RDWR|O_CLOEXEC"}}]`), "file.write", "tool wrote to /etc/hosts", 8},
		{tetragonPolicyLine("fd_install", `[{"int_arg":3},{"file_arg":{"path":"/etc/hosts","flags":"O_RDONLY"}}]`), "file.read", "tool read /etc/hosts", 8},
		{tetragonPolicyLine("file_open", `[]`), "file.access", "tool accessed a file", 6},
		{tetragonPolicyLine("security_path_truncate", `[{"path_arg":{"path":"/var/log/auth.log"}}]`), "file.write", "tool wrote to /var/log/auth.log", 8},
		{tetragonPolicyLine("security_bprm_check", `[{"linux_binprm_arg":{"path":"/tmp/payload"}}]`), "process.exec", "tool executed /tmp/payload", 8},
		{tetragonPolicyLine("security_bprm_check", `[]`), "process.exec", "tool executed a program", 8},
		{tetragonPolicyLine("do_init_module", `[{"module_arg":{"name":"evil","tainted":["TAINT_OOT_MODULE"]}}]`), "kernel.module.load", "tool loaded kernel module evil", 6},
		{tetragonPolicyLine("security_kernel_read_file", `[{"file_arg":{"path":"/lib/modules/x.ko"}},{"int_arg":2}]`), "kernel.module.load", "tool loaded kernel module /lib/modules/x.ko", 6},
		{tetragonPolicyLine("security_kernel_read_file", `[]`), "kernel.module.load", "tool loaded kernel module (unnamed)", 6},
		{tetragonPolicyLine("free_module", `[{"module_arg":{"name":"evil"}}]`), "kernel.module.unload", "tool removed kernel module evil", 4},
		{tetragonPolicyLine("free_module", `[]`), "kernel.module.unload", "tool removed kernel module (unnamed)", 4},
		{tetragonPolicyLine("bpf_check", `[{"bpf_attr_arg":{"ProgType":"BPF_PROG_TYPE_KPROBE","InsnCnt":12,"ProgName":"probe"}}]`), "kernel.bpf.load", "tool loaded BPF program probe (BPF_PROG_TYPE_KPROBE)", 6},
		{tetragonPolicyLine("bpf_check", `[]`), "kernel.bpf.load", "tool loaded BPF program (unnamed)", 6},
		{tetragonPolicyLine("tcp_connect", `[]`), "network.connect", "tool opened a connection", 8},
		{tetragonPolicyLine("some_other_hook", `[1,{"int_arg":"x"}]`), "tetragon.alert", "tool triggered some_other_hook", 5},
	} {
		e := parse(Config{}, s, tc.line, time.Now())
		if e.Action != tc.category || e.Summary != tc.description || e.Severity != tc.severity || e.Fields["tetragon.rule"] != "custom-policy" {
			t.Fatalf("%s: %+v", tc.line, e)
		}
	}
}

func TestTetragonNetworkTagsAndPrivacy(t *testing.T) {
	s := Source{Name: "tetragon", Parser: "tetragon"}
	e := parse(Config{}, s, tetragonReverseShell, time.Now())
	if e.Summary != "Shell connected out: bash opened a connection to port 4444" || e.Actor != "" || e.Fields["destination.ip"] != "203.0.113.9" || e.Fields["container.id"] != "0f3c2a9d81b7e4c" || e.Fields["tetragon.process.auid"] != "" {
		t.Fatal(e)
	}
	z := sealerFor(t, "events", "events")
	envs := classify(t, z, s, tetragonReverseShell)
	got := envs[0]["attributes"].(map[string]any)
	if got["rule_id"] != "anomaly-shell-network-connections" || got["category"] != "network.connect" || fmt.Sprint(got["groups"]) != "[process_kprobe tcp_connect action:post reverse-shell mitre:T1059]" {
		t.Fatal(got)
	}
	// Without a login uid, the process's own account is the subject.
	if r := recogniseTetragon(e); r.subject != "33" || envs[0]["subject"] == nil {
		t.Fatal(r)
	}
	if text := canonical(t, envs[0]); strings.Contains(text, "203.0.113.9") || strings.Contains(text, "172.17.0.5") {
		t.Fatal("address sent:", text)
	}
	// Account directories never leave the host, in fields or the envelope.
	e = parse(Config{}, s, tetragonHomeKeyRead, time.Now())
	if e.Summary != "backup-tool read /home/~/.ssh/id_ed25519" || e.Fields["process.executable"] != "/home/~/bin/backup-tool" || e.Fields["file.path"] != "/home/~/.ssh/id_ed25519" {
		t.Fatal(e)
	}
	if text := canonical(t, classify(t, z, s, tetragonHomeKeyRead)[0]); strings.Contains(text, "/home/alice") || !strings.Contains(text, "/home/~/.ssh/id_ed25519") {
		t.Fatal("account name sent:", text)
	}
	// A record without any account has no subject.
	noAccount := `{"process_kprobe":{"process":{"binary":"/usr/bin/x"},"function_name":"tcp_connect","policy_name":"p"},"time":"2026-11-25T06:00:00Z"}`
	if envs := classify(t, z, s, noAccount); len(envs) != 1 || envs[0]["subject"] != nil {
		t.Fatal(envs)
	}
	// In all_lines mode, other records are lines whose attributes leave out accounts.
	all := sealerFor(t, "all_lines", "all_lines")
	exit := `{"process_exit":{"process":{"pid":5,"uid":1001,"auid":1001,"binary":"/usr/bin/ls"},"parent":{"uid":1001}},"time":"2026-11-25T06:00:00Z"}`
	envs = classify(t, all, s, exit)
	if len(envs) != 1 || envs[0]["event_type"] != "log.line.collected" {
		t.Fatal(envs)
	}
	attrs := envs[0]["attributes"].(map[string]any)
	if attrs["action"] != "tetragon.process_exit" || attrs["process.name"] != "ls" || attrs["process.user.id"] != nil || attrs["tetragon.process.auid"] != nil || attrs["process.parent.user.id"] != nil {
		t.Fatal(attrs)
	}
	if len(classify(t, z, s, exit)) != 0 {
		t.Fatal("process exit became evidence")
	}
}

func TestTetragonPolicyAndTracepointNames(t *testing.T) {
	s := Source{Name: "tetragon", Parser: "tetragon"}
	tracepoint := `{"process_tracepoint":{"process":{"binary":"/usr/bin/x"},"subsys":"syscalls","event":"sys_enter_ptrace","policy_name":"Bad Name!","message":"ptrace used"},"time":"2026-11-25T06:00:00Z"}`
	e := parse(Config{}, s, tracepoint, time.Now())
	if e.Fields["tetragon.function"] != "syscalls/sys_enter_ptrace" || e.Fields["tetragon.policy.name"] != "" || e.Fields["tetragon.rule"] != "syscalls/sys_enter_ptrace" || e.Summary != "ptrace used: x triggered syscalls/sys_enter_ptrace" {
		t.Fatal(e)
	}
	uprobe := `{"process_uprobe":{"process":{"binary":"/usr/bin/bash"},"path":"/usr/bin/bash","symbol":"readline","policy_name":"bash-readline"},"time":"2026-11-25T06:00:00Z"}`
	if e := parse(Config{}, s, uprobe, time.Now()); e.Fields["tetragon.function"] != "readline" || e.Fields["tetragon.rule"] != "bash-readline" {
		t.Fatal(e)
	}
	lsm := `{"process_lsm":{"process":{"binary":"/usr/bin/x"},"function_name":"bprm_check_security","policy_name":"lsm-exec"},"time":"2026-11-25T06:00:00Z"}`
	if e := parse(Config{}, s, lsm, time.Now()); e.Action != "process.exec" {
		t.Fatal(e)
	}
	noProcess := `{"process_kprobe":{"function_name":"tcp_connect","policy_name":"p"},"time":"2026-11-25T06:00:00Z"}`
	if e := parse(Config{}, s, noProcess, time.Now()); e.Summary != "a process opened a connection" || e.Fields["process.name"] != "" {
		t.Fatal(e)
	}
	weird := strings.Replace(tetragonShadowRead, "/usr/bin/cat", "/usr/bin/c a;t", 1)
	if e := parse(Config{}, s, weird, time.Now()); e.Summary != "(unnamed) read /etc/shadow" {
		t.Fatal(e)
	}
}

func TestTetragonLevelOverrides(t *testing.T) {
	s := Source{Name: "tetragon", Parser: "tetragon", TetragonLevels: map[string]int{"anomaly-secret-reads": 10, "process_exec": 7}}
	if e := parse(Config{}, s, tetragonShadowRead, time.Now()); e.Severity != 10 || e.Fields["tetragon.level"] != "10" {
		t.Fatal(e)
	}
	if e := parse(Config{}, s, tetragonExecLine("/usr/bin/nc", "", 0, "/usr/bin/bash", 0), time.Now()); e.Severity != 7 {
		t.Fatal(e)
	}
	if e := parse(Config{}, s, tetragonSudo, time.Now()); e.Severity != 7 {
		t.Fatal(e)
	}
	if level := tetragonLevel(Source{}, "x", "no.such.category"); level != 5 {
		t.Fatal(level)
	}
}

func TestTetragonInvalidAndUnknownRecords(t *testing.T) {
	s := Source{Name: "tetragon", Parser: "tetragon"}
	now := time.Now().UTC()
	for _, raw := range []string{`not json`, `null`, `[]`, `{} {}`} {
		if e := parse(Config{}, s, raw, now); e.Fields["parse_status"] != "invalid_json" || e.Raw != raw {
			t.Fatal(e)
		}
	}
	e := parse(Config{}, s, `{"node_name":"web","time":"not a time","rate_limit_info":{"number_of_dropped_process_events":3}}`, now)
	if e.Fields["parse_status"] != "unknown_event" || !e.Timestamp.Equal(now) || e.Fields["timestamp_status"] != "collection_time_fallback" || e.Fields["tetragon.node.name"] != "web" {
		t.Fatal(e)
	}
	long := `{"process_kprobe":{"process":{"binary":"/usr/bin/x"},"function_name":"tcp_connect","policy_name":"p","message":"` + strings.Repeat("m", 5000) + `"},"time":"2026-11-25T06:00:00Z"}`
	if e := parse(Config{}, s, long, now); e.Fields["tetragon.message"] != "" || e.Summary != "x opened a connection" {
		t.Fatal("unbounded message kept")
	}
	var args []string
	for i := 0; i < 20; i++ {
		args = append(args, `{"int_arg":1}`)
	}
	args = append(args, `{"file_arg":{"path":"/etc/late"}}`)
	if e := parse(Config{}, s, tetragonPolicyLine("security_file_permission", "["+strings.Join(args, ",")+"]"), now); e.Fields["file.path"] != "" {
		t.Fatal("arguments past the bound were read")
	}
	if r := recogniseTetragon(Event{Fields: map[string]string{}}); r != nil {
		t.Fatal(r)
	}
}

func TestTetragonGroupsAreBounded(t *testing.T) {
	tags := []string{`"a,b"`, `"a b"`, `" "`, `"` + strings.Repeat("x", 129) + `"`}
	for i := 0; i < 40; i++ {
		tags = append(tags, fmt.Sprintf(`"tag-%d"`, i))
	}
	line := `{"process_kprobe":{"process":{"binary":"/usr/bin/x"},"function_name":"tcp_connect","policy_name":"p","tags":[` + strings.Join(tags, ",") + `]},"time":"2026-11-25T06:00:00Z"}`
	e := parse(Config{}, Source{Parser: "tetragon"}, line, time.Now())
	var groups []string
	if err := json.Unmarshal([]byte(e.Fields["tetragon.groups"]), &groups); err != nil {
		t.Fatal(err)
	}
	if len(groups) != 32 || groups[0] != "process_kprobe" || groups[2] != "a b" || groups[3] != "tag-0" {
		t.Fatal(groups)
	}
}

func TestTetragonElevatedCommand(t *testing.T) {
	for _, tc := range []struct{ mechanism, arguments, want string }{
		{"sudo", "su", "su"},
		{"sudo", "-u bob /usr/bin/apt update", "apt"},
		{"sudo", "-i", ""},
		{"sudo", "LANG=C FOO=1 /usr/bin/id -u", "id"},
		{"sudo", "-- ls -la", "ls"},
		{"sudo", "-E --", ""},
		{"sudo", "/home/alice/bin/a;b", ""},
		{"doas", "-u root vim /etc/hosts", "vim"},
		{"pkexec", "--user root gparted", "gparted"},
		{"su", "- root", ""},
		{"run0", "systemctl restart x", ""},
	} {
		if got := tetragonElevated(tc.mechanism, tc.arguments); got != tc.want {
			t.Fatalf("%s %s: %q, want %q", tc.mechanism, tc.arguments, got, tc.want)
		}
	}
	if tetragonPath("/home/alice") != "/home/~" || tetragonPath("/run/user/1001/bus") != "/run/user/~/bus" || tetragonPath("/home/") != "/home/" || tetragonBase("") != "" {
		t.Fatal("path normalisation")
	}
}

func TestTetragonRedactionFiltersAndCollection(t *testing.T) {
	c := Config{redactors: []*regexp.Regexp{regexp.MustCompile("hunter2")}}
	s := Source{Name: "tetragon", Parser: "tetragon", Kind: "file"}
	line := strings.Replace(tetragonShadowRead, `"arguments":"/etc/shadow"`, `"arguments":"--password hunter2"`, 1)
	if e := parse(c, s, line, time.Now()); strings.Contains(e.Raw, "hunter2") || e.Fields["file.path"] != "/etc/shadow" {
		t.Fatal(e.Raw)
	}
	e := parse(Config{}, s, tetragonShadowRead, time.Now())
	s.ExcludeMatch = "all"
	s.ExcludeWhen = []FieldFilter{{"tetragon.policy.name", "equals", "anomaly-secret-reads"}, {"process.parent.name", "equals", "bash"}}
	if keepStructured(s, e) {
		t.Fatal("AND exclusion did not match")
	}
	s.ExcludeWhen[1].Value = "sshd"
	if !keepStructured(s, e) {
		t.Fatal("partial AND excluded")
	}

	root := t.TempDir()
	path := filepath.Join(root, "tetragon.log")
	if err := os.WriteFile(path, []byte(tetragonSudo+"\n"+tetragonSudoChild+"\n"+line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sp := testSpool(t)
	s = Source{Name: "tetragon", Parser: "tetragon", Kind: "file", EvidenceMode: "events_with_lines"}
	if err := collectFile(c, s, sp, path); err != nil {
		t.Fatal(err)
	}
	batch, _ := sp.batch()
	if len(batch) != 2 || batch[0].EventType != "privileged.action.completed" || batch[1].EventType != "security.alert.generated" {
		t.Fatal(batch)
	}
	if p := payload(t, batch[1]); p == "" || strings.Contains(p, "hunter2") || strings.Contains(batch[1].Canonical, "hunter2") {
		t.Fatal("secret in payload or envelope")
	}
}

func TestTetragonConfiguration(t *testing.T) {
	source := "  - name: tetragon\n    kind: file\n    parser: tetragon\n    paths: [/var/log/tetragon/tetragon.log, /var/log/tetragon/tetragon-*.log]\n"
	for name, tc := range map[string]struct {
		text  string
		valid bool
	}{
		"plain":         {testConfig + source, true},
		"levels":        {testConfig + source + "    tetragon_levels:\n      anomaly-secret-reads: 10\n      process_exec: 0\n", true},
		"level_range":   {testConfig + source + "    tetragon_levels:\n      anomaly-secret-reads: 11\n", false},
		"level_name":    {testConfig + source + "    tetragon_levels:\n      Bad Name: 5\n", false},
		"other_parser":  {testConfig + "  - name: j\n    kind: journal\n    parser: syslog\n    tetragon_levels:\n      p: 5\n", false},
		"outside_log":   {testConfig + strings.Replace(source, "/var/log/tetragon/tetragon.log", "/var/run/cilium/tetragon/tetragon.log", 1), false},
		"too_many":      {testConfig + source + "    tetragon_levels:\n" + tetragonManyLevels(65), false},
		"just_enough":   {testConfig + source + "    tetragon_levels:\n" + tetragonManyLevels(64), true},
		"unknown_field": {testConfig + source + "    tetragon_level: 3\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := config(writeConfig(t, tc.text))
			if (err == nil) != tc.valid {
				t.Fatal(err)
			}
			if name == "levels" && c.Sources[0].TetragonLevels["anomaly-secret-reads"] != 10 {
				t.Fatal(c.Sources[0])
			}
		})
	}
}

func tetragonManyLevels(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "      policy-%d: 5\n", i)
	}
	return b.String()
}
