package main

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tetragon's JSON export holds one event per line: {"<kind>": {...},
// "node_name": ..., "time": ...}. Like OSSEC alerts it is data only, so the
// parser keeps a bounded set of namespaced fields. Account names never come
// from it; uids are kept for pseudonymous subjects and filters only.

// Kinds produced by tracing policies. Each carries the policy's name.
var tetragonPolicyKinds = []string{"process_kprobe", "process_tracepoint", "process_lsm", "process_uprobe", "process_usdt"}

// Policy names follow Kubernetes object names; process_exec names the level
// of watched program starts.
var tetragonPolicyName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,252}$`)

// The account-switching programs. A start of one under a non-root parent,
// running as root, is the moment privilege was gained.
var tetragonElevators = map[string]bool{"sudo": true, "su": true, "pkexec": true, "doas": true, "run0": true}

var tetragonShells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "csh": true, "tcsh": true, "fish": true, "ash": true}

// Network services whose shells are the shape of a web shell or injection.
var tetragonServices = regexp.MustCompile(`^(nginx|php-fpm[0-9.]*|postgres|gitea|forgejo|uvicorn|gunicorn|java|redis-server|valkey-server|httpd|apache2)$`)

// Programs named in descriptions and subjects of privileged actions.
var tetragonProgram = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

// Default levels on KEEN's 0..10 scale, by category.
var tetragonLevels = map[string]int{
	"file.read":                  8,
	"file.write":                 8,
	"file.access":                6,
	"process.exec":               8,
	"network.connect":            8,
	"kernel.module.load":         6,
	"kernel.module.unload":       4,
	"kernel.bpf.load":            6,
	"tetragon.alert":             5,
	"process.exec.service_shell": 9,
	"process.exec.watched":       3,
}

const tetragonUnsetAUID = "4294967295"

func parseTetragon(e *Event, s Source) {
	var data map[string]any
	if !jsonObject(e.Raw, &data) {
		e.Fields["parse_status"] = "invalid_json"
		return
	}
	put := func(key, value string) {
		if value != "" && len(value) <= 4096 {
			e.Fields[key] = value
		}
	}
	kind, body := "", map[string]any(nil)
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if object, ok := data[key].(map[string]any); ok && strings.HasPrefix(key, "process_") && len(key) <= 64 {
			kind, body = key, object
			break
		}
	}
	if stamp, err := time.Parse(time.RFC3339Nano, jsonValue(data["time"])); err == nil && stamp.Year() >= 1970 && stamp.Year() < 2262 {
		e.Timestamp = stamp.UTC()
	} else {
		e.Fields["timestamp_status"] = "collection_time_fallback"
	}
	put("tetragon.node.name", jsonValue(data["node_name"]))
	if kind == "" {
		e.Fields["parse_status"] = "unknown_event"
		return
	}
	e.Action = "tetragon." + kind
	put("tetragon.event", kind)
	get := func(path string) string { return jsonValue(jsonLookup(body, path)) }

	process := tetragonPath(get("process.binary"))
	parent := tetragonPath(get("parent.binary"))
	name, parentName := tetragonBase(process), tetragonBase(parent)
	put("process.executable", process)
	put("process.name", name)
	put("process.pid", get("process.pid"))
	put("process.user.id", get("process.uid"))
	put("tetragon.process.exec_id", get("process.exec_id"))
	put("process.parent.executable", parent)
	put("process.parent.name", parentName)
	put("process.parent.pid", get("parent.pid"))
	put("process.parent.user.id", get("parent.uid"))
	put("container.id", get("process.docker"))
	// The login uid survives sudo and su; 4294967295 means none was set.
	auid := get("process.auid")
	if auid != tetragonUnsetAUID {
		put("tetragon.process.auid", auid)
		e.Actor = auid
	}

	if kind == "process_exec" {
		tetragonExec(e, s, name, parentName, get("process.arguments"))
		return
	}
	isPolicy := false
	for _, k := range tetragonPolicyKinds {
		isPolicy = isPolicy || k == kind
	}
	if !isPolicy {
		return
	}

	policy := get("policy_name")
	function := get("function_name")
	switch kind {
	case "process_tracepoint":
		if subsys, event := get("subsys"), get("event"); subsys != "" && event != "" {
			function = subsys + "/" + event
		}
	case "process_uprobe", "process_usdt":
		if function == "" {
			function = get("symbol")
		}
	}
	if !tetragonPolicyName.MatchString(policy) {
		policy = ""
	}
	put("tetragon.policy.name", policy)
	put("tetragon.function", function)
	put("tetragon.action", get("action"))
	put("tetragon.message", get("message"))

	args, _ := body["args"].([]any)
	var filePath, flags, module, progName, progType, port string
	mask, hasMask := int64(0), false
	for i, item := range args {
		arg, ok := item.(map[string]any)
		if !ok || i >= 16 {
			continue
		}
		for _, key := range []string{"file_arg", "path_arg", "linux_binprm_arg"} {
			if v, ok := arg[key].(map[string]any); ok && filePath == "" {
				filePath, flags = tetragonPath(jsonValue(v["path"])), jsonValue(v["flags"])
			}
		}
		if v, ok := arg["module_arg"].(map[string]any); ok && module == "" {
			module = jsonValue(v["name"])
		}
		if v, ok := arg["bpf_attr_arg"].(map[string]any); ok && progType == "" {
			progName, progType = jsonValue(v["ProgName"]), jsonValue(v["ProgType"])
		}
		if v, ok := arg["sock_arg"].(map[string]any); ok && port == "" {
			port = jsonValue(v["dport"])
			put("destination.ip", jsonValue(v["daddr"]))
		}
		if n, err := strconv.ParseInt(jsonValue(arg["int_arg"]), 10, 64); err == nil && !hasMask && filePath != "" {
			mask, hasMask = n, true
		}
	}
	put("file.path", filePath)
	put("tetragon.file.flags", flags)
	if hasMask {
		put("tetragon.file.mask", strconv.FormatInt(mask, 10))
	}
	put("tetragon.module.name", module)
	put("tetragon.bpf.program_name", progName)
	put("tetragon.bpf.program_type", progType)
	put("destination.port", port)

	category := tetragonCategory(function, mask, hasMask, flags)
	e.Action = category
	actor := name
	if actor == "" {
		actor = "a process"
	}
	description := actor + " triggered " + function
	switch category {
	case "file.read":
		description = actor + " read " + tetragonOr(filePath, "a file")
	case "file.write":
		description = actor + " wrote to " + tetragonOr(filePath, "a file")
	case "file.access":
		description = actor + " accessed " + tetragonOr(filePath, "a file")
	case "process.exec":
		description = actor + " executed " + tetragonOr(filePath, "a program")
	case "kernel.module.load":
		description = actor + " loaded kernel module " + tetragonOr(module, tetragonOr(filePath, "(unnamed)"))
	case "kernel.module.unload":
		description = actor + " removed kernel module " + tetragonOr(module, "(unnamed)")
	case "kernel.bpf.load":
		description = actor + " loaded BPF program " + tetragonOr(progName, "(unnamed)")
		if progType != "" {
			description += " (" + progType + ")"
		}
	case "network.connect":
		// The address stays on the host; filters can still use it.
		description = actor + " opened a connection"
		if port != "" {
			description += " to port " + port
		}
	}
	if message := e.Fields["tetragon.message"]; message != "" {
		description = message + ": " + description
	}
	tetragonAlert(e, s, policy, category, description)

	groups := []string{kind}
	if function != "" {
		groups = append(groups, function)
	}
	if action := strings.ToLower(strings.TrimPrefix(get("action"), "KPROBE_ACTION_")); action != "" {
		groups = append(groups, "action:"+action)
	}
	if tags, ok := body["tags"].([]any); ok {
		for _, tag := range tags {
			groups = append(groups, jsonValue(tag))
		}
	}
	tetragonGroups(e, groups)
}

// tetragonExec classifies a program start that passed the export allow-list.
func tetragonExec(e *Event, s Source, name, parentName, arguments string) {
	uid, parentUID := e.Fields["process.user.id"], e.Fields["process.parent.user.id"]
	if tetragonElevators[name] {
		if uid != "0" || parentUID == "" || parentUID == "0" {
			// sudo's own child and the su it starts: the same escalation again.
			e.Fields["tetragon.exec.kind"] = "privilege_child"
			return
		}
		e.Action = "privilege.gained"
		e.Outcome = "success"
		e.Fields["tetragon.exec.kind"] = "privilege"
		e.Fields["tetragon.privilege.mechanism"] = name
		if elevated := tetragonElevated(name, arguments); elevated != "" {
			e.Fields["tetragon.privilege.executable"] = elevated
		}
		if e.Actor == "" {
			e.Actor = parentUID
		}
		e.Summary = tetragonOr(parentName, "a process") + " gained root through " + name
		e.Severity = tetragonLevel(s, "process_exec", "process.exec.watched")
		return
	}
	category, kind := "process.exec.watched", "watched"
	if tetragonShells[name] && tetragonServices.MatchString(parentName) {
		category, kind = "process.exec.service_shell", "service_shell"
	}
	e.Fields["tetragon.exec.kind"] = kind
	e.Action = category
	description := tetragonOr(name, "a program") + " started by " + tetragonOr(parentName, "an unknown parent")
	tetragonAlert(e, s, "process_exec", category, description)
	groups := []string{"process_exec", name}
	if parentName != "" {
		groups = append(groups, "parent:"+parentName)
	}
	if uid == "0" && parentUID != "" && parentUID != "0" {
		groups = append(groups, "setuid")
	}
	tetragonGroups(e, groups)
}

func tetragonAlert(e *Event, s Source, rule, category, description string) {
	if rule == "" {
		rule = e.Fields["tetragon.function"]
	}
	level := tetragonLevel(s, rule, category)
	e.Severity = level
	e.Summary = description
	e.Fields["tetragon.alert"] = "true"
	e.Fields["tetragon.rule"] = rule
	e.Fields["tetragon.level"] = strconv.Itoa(level)
	e.Fields["tetragon.description"] = description
}

func tetragonLevel(s Source, rule, category string) int {
	if level, ok := s.TetragonLevels[rule]; ok {
		return level
	}
	if level, ok := tetragonLevels[category]; ok {
		return level
	}
	return tetragonLevels["tetragon.alert"]
}

// tetragonCategory names what a policy hook observed, independent of what
// the policy is called. mask is the kernel's MAY_* access mask.
func tetragonCategory(function string, mask int64, hasMask bool, flags string) string {
	switch function {
	case "security_file_permission", "security_file_open", "file_open", "file_permission", "fd_install", "security_mmap_file":
		const mayWrite, mayRead, mayAppend = 2, 4, 8
		switch {
		case hasMask && mask&(mayWrite|mayAppend) != 0:
			return "file.write"
		case hasMask && mask&mayRead != 0:
			return "file.read"
		case !hasMask && flags != "":
			for _, flag := range []string{"O_WRONLY", "O_RDWR", "O_TRUNC", "O_APPEND", "O_CREAT"} {
				if strings.Contains(flags, flag) {
					return "file.write"
				}
			}
			return "file.read"
		}
		return "file.access"
	case "security_path_truncate", "security_inode_rename", "security_path_unlink", "security_inode_unlink", "security_path_rename":
		return "file.write"
	case "security_bprm_check", "bprm_check_security", "security_bprm_creds_for_exec":
		return "process.exec"
	case "do_init_module", "security_kernel_read_file", "kernel_read_file", "security_kernel_load_data", "kernel_load_data":
		return "kernel.module.load"
	case "free_module", "delete_module", "__x64_sys_delete_module", "__arm64_sys_delete_module":
		return "kernel.module.unload"
	case "bpf_check", "security_bpf_prog_load", "bpf_prog_load", "security_bpf_prog":
		return "kernel.bpf.load"
	case "tcp_connect", "security_socket_connect", "socket_connect", "udp_sendmsg", "ip4_datagram_connect":
		return "network.connect"
	}
	return "tetragon.alert"
}

// tetragonElevated names the program sudo, doas or pkexec ran, when its name
// is a plain program name. su and run0 start a shell or a unit; none is named.
func tetragonElevated(mechanism, arguments string) string {
	valued := map[string]bool{}
	switch mechanism {
	case "sudo":
		for _, option := range []string{"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T", "-R", "--user", "--group", "--close-from", "--chdir", "--host", "--prompt", "--role", "--type", "--other-user", "--command-timeout", "--chroot"} {
			valued[option] = true
		}
	case "doas":
		valued["-u"], valued["-C"] = true, true
	case "pkexec":
		valued["--user"] = true
	default:
		return ""
	}
	words := strings.Fields(arguments)
	for i := 0; i < len(words) && i < 64; i++ {
		word := words[i]
		switch {
		case word == "--":
			if i+1 < len(words) {
				return tetragonCommand(words[i+1])
			}
			return ""
		case strings.HasPrefix(word, "-"):
			if valued[word] {
				i++
			}
		case strings.Contains(word, "=") && !strings.Contains(word, "/"):
			// An environment assignment before the command.
		default:
			return tetragonCommand(word)
		}
	}
	return ""
}

func tetragonCommand(word string) string {
	if name := path.Base(word); tetragonProgram.MatchString(name) {
		return name
	}
	return ""
}

// tetragonPath replaces the account directory in a path, which can name a
// person: /home/alice/.ssh/id_ed25519 becomes /home/~/.ssh/id_ed25519.
func tetragonPath(p string) string {
	for _, root := range []string{"/home/", "/var/home/", "/run/user/"} {
		if rest, ok := strings.CutPrefix(p, root); ok && rest != "" {
			if _, tail, found := strings.Cut(rest, "/"); found {
				return root + "~/" + tail
			}
			return root + "~"
		}
	}
	return p
}

func tetragonBase(p string) string {
	if p == "" {
		return ""
	}
	if name := path.Base(p); tetragonProgram.MatchString(name) {
		return name
	}
	return "(unnamed)"
}

func tetragonOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// tetragonGroups keeps up to 32 unique, comma-free groups in their order.
func tetragonGroups(e *Event, groups []string) {
	seen := map[string]bool{}
	kept := []string{}
	for _, group := range groups {
		group = strings.TrimSpace(strings.ReplaceAll(group, ",", " "))
		if group == "" || len(group) > 128 || seen[group] || len(kept) >= 32 {
			continue
		}
		seen[group] = true
		kept = append(kept, group)
	}
	encoded, _ := json.Marshal(kept)
	e.Fields["tetragon.groups"] = string(encoded)
}

// recogniseTetragon maps policy alerts and watched program starts to
// security.alert.generated, and gaining root to privileged.action.completed.
// The login uid (or the invoking uid) becomes a pseudonymous subject.
func recogniseTetragon(e Event) *recognised {
	f := e.Fields
	subject := f["tetragon.process.auid"]
	switch {
	case f["tetragon.exec.kind"] == "privilege":
		if subject == "" {
			subject = f["process.parent.user.id"]
		}
		return &recognised{"privileged.action.completed", "tetragon", "execute", map[string]string{
			"mechanism": f["tetragon.privilege.mechanism"], "executable": f["tetragon.privilege.executable"], "audit_type": "process_exec",
		}, tetragonSubjectKind(subject), subject}
	case f["tetragon.alert"] == "true":
		if subject == "" {
			subject = f["process.user.id"]
		}
		var groups []string
		_ = json.Unmarshal([]byte(f["tetragon.groups"]), &groups)
		return &recognised{"security.alert.generated", "tetragon", "alert", map[string]string{
			"product": "tetragon", "rule_id": f["tetragon.rule"], "level": f["tetragon.level"], "description": f["tetragon.description"],
			"groups": strings.Join(groups, ","), "category": e.Action,
		}, tetragonSubjectKind(subject), subject}
	}
	return nil
}

func tetragonSubjectKind(uid string) string {
	if uid == "" {
		return ""
	}
	return "unix_uid"
}
