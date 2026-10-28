package main

import (
	"path"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"keen-agent/internal/agentauth"
	"keen-agent/internal/ueu"
)

// sealer turns parsed records into envelopes for one enrolled identity.
type sealer struct {
	producer ueu.Producer
	ceiling  ueu.Mode
	fallback ueu.Mode
}

func newSealer(c Config, id agentauth.Identity) (*sealer, error) {
	subject, err := id.Subject()
	if err != nil {
		return nil, err
	}
	asset := id.AssetType
	if asset == "" {
		asset = "server"
	}
	fallback, err := ueu.ParseMode(c.EvidenceMode)
	if err != nil {
		return nil, err
	}
	return &sealer{
		producer: ueu.Producer{Catalogue: ueu.KEEN(), ApplicationID: "keen-agent", ApplicationVersion: version, InstanceID: id.AgentID, AssetType: asset, Platform: runtime.GOOS, Subject: subject},
		ceiling:  id.EvidenceCeiling(),
		fallback: fallback,
	}, nil
}

// mode is the source's configured evidence mode, limited by KEEN's ceiling.
func (z *sealer) mode(s Source) (ueu.Mode, bool) {
	m := z.fallback
	if s.EvidenceMode != "" {
		m, _ = ueu.ParseMode(s.EvidenceMode)
	}
	if !m.Within(z.ceiling) {
		return z.ceiling, true
	}
	return m, false
}

// envelopes classifies one parsed record. A record that is not evidence in
// the source's mode returns no envelopes and is counted, not sent.
func (z *sealer) envelopes(s Source, e Event) ([]map[string]any, error) {
	switch {
	case e.Posture != nil:
		return z.observation(e)
	case e.Coverage != nil:
		return z.coverage(e)
	}
	mode, _ := z.mode(s)
	if r := recognise(s, e); r != nil {
		env, err := z.producer.Emit(ueu.Event{
			Type: r.eventType, Component: r.component, Action: r.action, Outcome: outcome(e.Outcome), Time: e.Timestamp,
			Attributes: r.attributes, SubjectKind: r.subjectKind, SubjectValue: r.subject,
			SourceRecord: e.Raw, IncludePayload: mode.IncludesLines(), Mode: mode, SupportingRecord: e.Ref,
		})
		if err != nil {
			return nil, err
		}
		return []map[string]any{env}, nil
	}
	if mode != ueu.ModeAllLines {
		return nil, nil
	}
	env, err := z.producer.Emit(ueu.Event{
		Type: "log.line.collected", Component: s.Parser, Action: "collect", Outcome: outcome(e.Outcome), Time: e.Timestamp,
		Attributes: lineAttributes(s, e), SourceRecord: e.Raw, IncludePayload: true, Mode: mode, SupportingRecord: e.Ref,
	})
	if err != nil {
		return nil, err
	}
	return []map[string]any{env}, nil
}

func outcome(v string) string {
	switch v {
	case "success", "failure":
		return v
	}
	return "info"
}

func (z *sealer) observation(e Event) ([]map[string]any, error) {
	o := *e.Posture
	kind, value, scope := ueu.LocalAccount(o.Scope)
	method := "linux_host_collector"
	if e.Authority == "user_session" {
		method = "linux_session_collector"
		kind, value = "unix_uid", e.Fields["_UID"]
	}
	env, err := z.producer.Observe(ueu.Observation{
		Check: o.Check, Provider: o.Provider, Scope: scope, Status: o.Status, Reason: o.Reason, Facts: o.Facts,
		ObservedAt: e.Timestamp, SubjectKind: kind, SubjectValue: value, Method: method, ValidFor: 24 * time.Hour,
	})
	if err != nil {
		return nil, err
	}
	return []map[string]any{env}, nil
}

func (z *sealer) coverage(e Event) ([]map[string]any, error) {
	c := *e.Coverage
	observed := map[string]bool{}
	for _, v := range c.Observed {
		observed[v] = true
	}
	var unavailable []string
	for _, v := range c.Attempted {
		if !observed[v] {
			unavailable = append(unavailable, v)
		}
	}
	env, err := z.producer.Emit(ueu.Event{
		Type: "evidence.collection.completed", Component: c.Collector, Action: "collect", Outcome: "info", Time: e.Timestamp,
		Attributes: map[string]string{
			"collector": c.Collector, "run_id": c.RunID,
			"checks_attempted": strings.Join(c.Attempted, ","), "checks_observed": strings.Join(c.Observed, ","),
			"checks_unavailable": strings.Join(unavailable, ","), "probes_unavailable": strings.Join(c.Unavailable, ","),
			"checks_attempted_count": strconv.Itoa(len(c.Attempted)), "checks_observed_count": strconv.Itoa(len(c.Observed)),
		},
	})
	if err != nil {
		return nil, err
	}
	return []map[string]any{env}, nil
}

// recognised is a log record that matches a catalogue event type.
type recognised struct {
	eventType, component, action string
	attributes                   map[string]string
	subjectKind, subject         string
}

var (
	sshdLogin   = regexp.MustCompile(`(Accepted|Failed) (publickey|password|keyboard-interactive/pam|gssapi-with-mic|hostbased) for (?:invalid user )?(\S{1,64}) from `)
	sudoCommand = regexp.MustCompile(`(?:^|\s)(\S{1,64}) : (?:[^;\n]*; )*COMMAND=(\S{1,1000})`)
	aptPackage  = regexp.MustCompile(`([^\s,()]{1,128}) \([^)]*\)`)
	aptUser     = regexp.MustCompile(`^(\S{1,64})`)
)

func recognise(s Source, e Event) *recognised {
	f := e.Fields
	switch s.Parser {
	case "dpkg":
		switch e.Action {
		case "package.install", "package.upgrade", "package.remove", "package.purge":
			action := strings.TrimPrefix(e.Action, "package.")
			return &recognised{"software.package.changed", "dpkg", action, map[string]string{
				"manager": "dpkg", "action": action, "package": f["package"], "old_version": f["old_version"], "new_version": f["new_version"],
			}, "", ""}
		}
	case "apt":
		if e.Action != "package.transaction" {
			return nil
		}
		var packages []string
		for _, action := range []string{"install", "upgrade", "remove", "purge", "downgrade"} {
			for _, m := range aptPackage.FindAllStringSubmatch(f[action], 64) {
				if len(packages) < ueu.MaxListItems {
					packages = append(packages, action+":"+m[1])
				}
			}
		}
		attributes := map[string]string{"manager": "apt", "action": "transaction", "packages": strings.Join(packages, ","), "transaction_complete": strconv.FormatBool(f["transaction_end_recorded"] == "true")}
		r := &recognised{"software.package.changed", "apt", "transaction", attributes, "", ""}
		if m := aptUser.FindStringSubmatch(f["requested_by"]); m != nil {
			r.subjectKind, r.subject = "unix_user", m[1]
		}
		return r
	case "dnf":
		if strings.HasPrefix(e.Action, "package.") && e.Action != "package.record" {
			action := strings.TrimPrefix(e.Action, "package.")
			return &recognised{"software.package.changed", "dnf", action, map[string]string{"manager": "dnf", "action": action, "package": f["package"]}, "", ""}
		}
	case "syslog":
		if m := sshdLogin.FindStringSubmatch(e.Raw); m != nil && (e.Action == "authentication.accepted" || e.Action == "authentication.failed") {
			return &recognised{"user.authenticated", "sshd", "authenticate", map[string]string{"service": "sshd", "method": m[2]}, "unix_user", m[3]}
		}
		if strings.ToLower(f["process.name"]) == "sudo" {
			if m := sudoCommand.FindStringSubmatch(e.Raw); m != nil {
				return &recognised{"privileged.action.completed", "sudo", "execute", map[string]string{"mechanism": "sudo", "executable": path.Base(m[2])}, "unix_user", m[1]}
			}
		}
	case "auditd":
		kind := f["type"]
		r := &recognised{component: "auditd", attributes: map[string]string{"audit_type": kind}}
		if auid := f["auid"]; auid != "" && auid != "4294967295" && auid != "-1" {
			r.subjectKind, r.subject = "unix_uid", auid
		}
		executable := path.Base(strings.Trim(f["exe"], `"`))
		if executable == "." || executable == "/" {
			executable = ""
		}
		switch kind {
		case "USER_AUTH", "USER_LOGIN":
			r.eventType, r.action = "user.authenticated", "authenticate"
			r.attributes["service"], r.attributes["method"] = executable, strings.ToLower(kind)
			if acct := strings.Trim(f["acct"], `"`); acct != "" && acct != "?" {
				r.subjectKind, r.subject = "unix_user", acct
			}
		case "USER_CMD":
			r.eventType, r.action = "privileged.action.completed", "execute"
			r.attributes["mechanism"], r.attributes["executable"] = "auditd", executable
		case "SYSCALL":
			if f["success"] != "no" {
				return nil
			}
			r.eventType, r.action = "access.denied", "deny"
			r.attributes["syscall"], r.attributes["executable"] = f["syscall"], executable
		default:
			return nil
		}
		return r
	case "ossec":
		if f["ossec.rule.id"] == "" {
			return nil
		}
		groups := ""
		if g := f["ossec.rule.groups"]; strings.HasPrefix(g, "[") {
			var list []string
			for _, item := range strings.Split(strings.Trim(g, "[]"), ",") {
				list = append(list, strings.Trim(strings.TrimSpace(item), `"`))
			}
			groups = strings.Join(list, ",")
		}
		return &recognised{"security.alert.generated", "ossec", "alert", map[string]string{
			"product": "ossec", "rule_id": f["ossec.rule.id"], "level": f["ossec.rule.level"], "description": f["ossec.rule.description"],
			"groups": groups, "category": e.Action,
		}, "", ""}
	}
	return nil
}

var lineField = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

// lineAttributes keeps parser enrichment useful for mapping rules, leaving
// out identifiers of people and addresses; the line itself is the payload.
func lineAttributes(s Source, e Event) map[string]string {
	out := map[string]string{"source": s.Name, "parser": s.Parser, "action": e.Action}
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(out) >= 40 || !lineField.MatchString(k) || personalField(k) {
			continue
		}
		if _, taken := out[k]; !taken && len(e.Fields[k]) <= ueu.MaxString {
			out[k] = e.Fields[k]
		}
	}
	return out
}

func personalField(k string) bool {
	for _, marker := range []string{"ip", "user", "acct", "uid", "addr", "email", "cursor", "auid", "srcuser", "dstuser"} {
		for _, part := range strings.FieldsFunc(k, func(r rune) bool { return r == '.' || r == '_' }) {
			if part == marker {
				return true
			}
		}
	}
	return false
}
