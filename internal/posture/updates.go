package posture

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// INI parsing is intentionally strict; include directives and malformed lines
// are not silently treated as valid/default configuration.
func ini(raw []byte) (map[string]string, bool) {
	m := map[string]string{}
	section := ""
	valid := true
	for _, l := range strings.Split(string(raw), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			section = strings.ToLower(strings.TrimSpace(l[1 : len(l)-1]))
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok || section == "" {
			valid = false
			continue
		}
		m[section+"."+strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return m, valid
}

var aptLine = regexp.MustCompile(`^([A-Za-z0-9_:.-]+)\s+"([^"\r\n]*)";$`)

func aptConfig(raw string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(raw, "\n") {
		if f := aptLine.FindStringSubmatch(strings.TrimSpace(l)); f != nil {
			m[f[1]] = f[2]
		}
	}
	return m
}
func intervalEnabled(v string) (bool, bool) {
	if v == "always" {
		return true, true
	}
	n, ok := number(v)
	return n > 0, ok
}
func addService(o *Observation, ctx context.Context, s System, timer, service string) {
	t := unit(ctx, s, timer)
	u := unit(ctx, s, service)
	o.Facts["timer"] = timer
	if t == nil {
		o.Facts["scheduler_state"] = "unknown"
	} else if t["LoadState"] != "loaded" {
		o.Facts["scheduler_state"] = "not_loaded"
	} else {
		o.Facts["scheduler_state"] = t["ActiveState"]
		o.Facts["scheduler_enabled"] = t["UnitFileState"]
		if v := t["LastTriggerUSec"]; v != "" {
			o.Facts["last_trigger"] = v
		}
	}
	if u != nil && u["LoadState"] == "loaded" {
		if u["DropInPaths"] != "" {
			o.Facts["service_has_overrides"] = "true"
			o.Facts["configuration_effective"] = "unknown"
		}
		if v := u["ConditionResult"]; v != "" {
			boolFact(o, "last_service_conditions_met", v)
		}
		for k, v := range map[string]string{"last_service_result": u["Result"], "last_service_exit_code": u["ExecMainStatus"], "last_service_exit": u["ExecMainExitTimestamp"]} {
			if v != "" {
				o.Facts[k] = v
			}
		}
		// A successful wrapper may have skipped work (battery, locks, conditions).
		o.Facts["execution_evidence"] = "scheduler_service_only"
	}
}
func Updates(ctx context.Context, s System) []Observation {
	var out []Observation
	o := observation("automatic_updates", "apt", "host")
	raw, e := query(ctx, s, "apt-config", "dump")
	if e == nil {
		m := aptConfig(raw)
		if pkg, e := query(ctx, s, "dpkg-query", "--show", "--showformat=${db:Status-Status}", "unattended-upgrades"); e == nil {
			o.Facts["unattended_upgrades_installed"] = strconv.FormatBool(pkg == "installed")
		}
		o.Status = "observed"
		o.Reason = "effective_configuration_queried"
		enabled := true
		if v, ok := m["APT::Periodic::Enable"]; ok {
			var valid bool
			enabled, valid = yes(v)
			if !valid {
				o.Status = "unknown"
				o.Reason = "invalid_periodic_enable"
			}
		}
		v, exists := m["APT::Periodic::Unattended-Upgrade"]
		if !exists {
			v = "0"
		}
		on, ok := intervalEnabled(v)
		if !ok {
			o = failed(o, "unrecognised_upgrade_interval")
		} else if o.Status == "observed" {
			o.Facts["automatic_install_configured"] = strconv.FormatBool(enabled && on)
		}
		o.Facts["install_interval_days_or_always"] = v
		if v := m["APT::Periodic::Update-Package-Lists"]; v != "" {
			o.Facts["refresh_interval_days_or_always"] = v
		}
		// apt-config emits array entries separately; count, don't leak repository URLs.
		origins, blocked := 0, 0
		for _, l := range strings.Split(raw, "\n") {
			if strings.HasPrefix(l, "Unattended-Upgrade::Allowed-Origins:: ") || strings.HasPrefix(l, "Unattended-Upgrade::Origins-Pattern:: ") {
				origins++
			}
			if strings.HasPrefix(l, "Unattended-Upgrade::Package-Blacklist:: ") {
				blocked++
			}
		}
		o.Facts["allowed_origin_entries"] = strconv.Itoa(origins)
		o.Facts["blacklist_entries"] = strconv.Itoa(blocked)
		o.Facts["package_scope"] = "configured_origins_and_exclusions"
		for _, k := range []string{"OnlyOnACPower", "Automatic-Reboot"} {
			if v := m["Unattended-Upgrade::"+k]; v != "" {
				boolFact(&o, strings.ToLower(strings.ReplaceAll(k, "-", "_")), v)
			}
		}
		addService(&o, ctx, s, "apt-daily-upgrade.timer", "apt-daily-upgrade.service")
		aptHistory(s, &o)
		if _, e := s.Read("/run/reboot-required"); e == nil {
			o.Facts["reboot_required"] = "true"
		}
		// Absence of this Ubuntu/Debian marker is not universal proof no reboot is needed.
	} else {
		o.Reason = "apt_configuration_unavailable"
	}
	out = append(out, o)
	for _, spec := range []struct {
		provider, path, timer, service string
		force                          bool
	}{
		{"dnf", "/etc/dnf/automatic.conf", "dnf-automatic.timer", "dnf-automatic.service", false},
		{"dnf_install", "/etc/dnf/automatic.conf", "dnf-automatic-install.timer", "dnf-automatic-install.service", true},
		{"dnf5", "/etc/dnf/automatic.conf", "dnf5-automatic.timer", "dnf5-automatic.service", false},
	} {
		o := observation("automatic_updates", spec.provider, "host")
		raw, e := s.Read(spec.path)
		if spec.provider == "dnf5" {
			vendor, ve := s.Read("/usr/share/dnf5/dnf5-plugins/automatic.conf")
			if ve == nil && (e == nil || errors.Is(e, os.ErrNotExist)) {
				base, bok := ini(vendor)
				override, ook := ini(raw)
				if !bok || !ook {
					out = append(out, failed(o, "unrecognised_automatic_configuration"))
					continue
				}
				for k, v := range override {
					base[k] = v
				}
				// Only the commands section is needed; other sections can
				// contain SMTP credentials and executable emitter templates.
				raw = []byte("[commands]\n")
				for _, k := range []string{"apply_updates", "download_updates", "upgrade_type", "reboot"} {
					if v, ok := base["commands."+k]; ok {
						raw = append(raw, []byte(k+"="+v+"\n")...)
					}
				}
				e = nil
				o.Facts["vendor_defaults_loaded"] = "true"
			} else if ve != nil && !errors.Is(ve, os.ErrNotExist) {
				e = ve
			}
		}
		if e != nil {
			o.Reason = "automatic_configuration_unavailable"
			out = append(out, o)
			continue
		}
		m, valid := ini(raw)
		if !valid {
			out = append(out, failed(o, "unrecognised_automatic_configuration"))
			continue
		}
		apply := false
		ok := true
		if v, exists := m["commands.apply_updates"]; exists {
			apply, ok = yes(v)
		}
		if !ok {
			out = append(out, failed(o, "invalid_apply_updates"))
			continue
		}
		if spec.force {
			apply = true
		}
		o.Status = "observed"
		o.Reason = "configuration_and_scheduler_queried"
		o.Facts["automatic_install_configured"] = strconv.FormatBool(apply)
		scope := m["commands.upgrade_type"]
		if scope == "" {
			scope = "default"
		}
		o.Facts["package_scope"] = scope
		addService(&o, ctx, s, spec.timer, spec.service)
		o.Facts["configuration_basis"] = "standard_unit_configuration_path"
		// Unit overrides may use a different file. Never call this effective policy.
		out = append(out, o)
	}
	o = observation("automatic_updates", "rpm_ostree", "host")
	rawBytes, e := s.Read("/etc/rpm-ostreed.conf")
	if e == nil {
		m, ok := ini(rawBytes)
		if !ok {
			o.Reason = "invalid_rpm_ostree_configuration"
		} else {
			p := strings.ToLower(m["daemon.automaticupdatepolicy"])
			if p == "" {
				p = "none"
			}
			switch p {
			case "none", "check", "stage", "apply":
				o.Status = "observed"
				o.Reason = "configuration_queried"
				o.Facts["policy"] = p
				o.Facts["automatic_install_configured"] = strconv.FormatBool(p == "apply")
				o.Facts["deployment_activation"] = "requires_separate_verification"
			default:
				o.Reason = "unrecognised_update_policy"
			}
			addService(&o, ctx, s, "rpm-ostreed-automatic.timer", "rpm-ostreed-automatic.service")
		}
	} else {
		o.Reason = "rpm_ostree_configuration_unavailable"
	}
	out = append(out, o)
	return out
}
func parseTime(v string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "Mon 2006-01-02 15:04:05 MST", "2006-01-02 15:04:05", "02 Jan 2006 15:04 -0700"} {
		if t, e := time.Parse(layout, v); e == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// These records supplement configuration; a previous success never suppresses
// a later error. Raw package lists, repository URLs and mail addresses stay local.
func aptHistory(s System, o *Observation) {
	var lastRun, lastSuccess, lastError string
	for _, path := range []string{"/var/log/unattended-upgrades/unattended-upgrades.log.1", "/var/log/unattended-upgrades/unattended-upgrades.log"} {
		b, e := s.Tail(path)
		if e != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if len(line) < 20 {
				continue
			}
			stamp := line[:19]
			if _, e := time.Parse("2006-01-02 15:04:05", stamp); e != nil {
				continue
			}
			if strings.Contains(line, "Starting unattended upgrades script") && stamp > lastRun {
				lastRun = stamp
			}
			if (strings.Contains(line, "All upgrades installed") || strings.Contains(line, "No packages found that can be upgraded unattended")) && stamp > lastSuccess {
				lastSuccess = stamp
			}
			if strings.Contains(line, " ERROR ") && stamp > lastError {
				lastError = stamp
			}
		}
	}
	// Log timestamps have no offset. Preserve this fact instead of inventing UTC.
	if lastRun != "" {
		o.Facts["last_run_local_time"] = lastRun
		o.Facts["execution_evidence"] = "unattended_upgrades_log"
	}
	if lastSuccess != "" {
		o.Facts["last_success_local_time"] = lastSuccess
		o.Facts["execution_evidence"] = "unattended_upgrades_log"
	}
	if lastError != "" {
		o.Facts["last_error_local_time"] = lastError
	}
	if lastError != "" && lastSuccess != "" {
		o.Facts["error_after_last_success"] = strconv.FormatBool(lastError >= lastSuccess)
	}
	if lastRun != "" || lastSuccess != "" || lastError != "" {
		o.Facts["log_time_basis"] = "host_local_offset_not_recorded"
	}
}
