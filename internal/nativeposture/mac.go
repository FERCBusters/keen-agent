package nativeposture

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// CollectMac is injectable for fixture tests on non-Mac build hosts.
func CollectMac(ctx context.Context, r Runner) []Observation {
	var out []Observation
	if v, e := query(ctx, r, "/usr/bin/fdesetup", "status"); e == nil {
		f := map[string]string{"coverage": "startup_volume"}
		o := unavailable("disk_encryption", "filevault")
		if strings.Contains(v, "FileVault is On.") {
			f["enabled"] = "true"
			o = observed("disk_encryption", "filevault", "startup_volume", "filevault_status_observed", f)
		} else if strings.Contains(v, "FileVault is Off.") {
			f["enabled"] = "false"
			o = observed("disk_encryption", "filevault", "startup_volume", "filevault_status_observed", f)
		}
		if strings.Contains(strings.ToLower(v), "in progress") {
			o.Status = "observed"
			o.Reason = "encryption_transition"
			o.Facts = map[string]string{"transition_in_progress": "true"}
		}
		out = append(out, o)
	} else {
		out = append(out, unavailable("disk_encryption", "filevault"))
	}
	const fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	if v, e := query(ctx, r, fw, "--getglobalstate"); e == nil {
		f := map[string]string{}
		switch {
		case strings.Contains(v, "State = 0"):
			f["enabled"] = "false"
		case strings.Contains(v, "State = 1") || strings.Contains(v, "State = 2"):
			f["enabled"] = "true"
		}
		if len(f) > 0 {
			out = append(out, observed("firewall", "macos_application_firewall", "host", "firewall_state_observed", f))
		} else {
			out = append(out, unavailable("firewall", "macos_application_firewall"))
		}
	} else {
		out = append(out, unavailable("firewall", "macos_application_firewall"))
	}
	if v, e := query(ctx, r, "/sbin/pfctl", "-s", "info"); e == nil {
		f := map[string]string{}
		if strings.Contains(v, "Status: Enabled") {
			f["enabled"] = "true"
		} else if strings.Contains(v, "Status: Disabled") {
			f["enabled"] = "false"
		}
		if len(f) > 0 {
			out = append(out, observed("firewall", "macos_pf", "host", "packet_filter_state_observed", f))
		}
	}
	// Native malware protection: report installed Apple components and versions.
	for _, pkg := range []string{"com.apple.pkg.XProtectPlistConfigData", "com.apple.pkg.XProtectPayloads"} {
		raw, e := r.Run(ctx, "/usr/sbin/pkgutil", []string{"--pkg-info-plist", pkg}, nil)
		if e != nil {
			continue
		}
		m, e := plistJSON(ctx, r, raw)
		if e != nil {
			continue
		}
		f := map[string]string{"installed": "true"}
		if v, ok := m["pkg-version"].(string); ok {
			f["version"] = v
		}
		if v, ok := m["install-time"].(float64); ok {
			f["installed_unix_seconds"] = strconv.FormatInt(int64(v), 10)
		}
		out = append(out, observed("antivirus", "apple_xprotect", pkg, "components_detected", f))
	}
	// Only fixed whitelisted health fields, never full vendor configuration.
	if raw, e := r.Run(ctx, "/usr/local/bin/mdatp", []string{"health", "--output", "json"}, nil); e == nil {
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			f := map[string]string{}
			for _, k := range []string{"healthy", "real_time_protection_enabled", "passive_mode_enabled", "definitions_updated", "definitions_version"} {
				switch v := m[k].(type) {
				case bool:
					f[k] = strconv.FormatBool(v)
				case string:
					if len(v) <= 256 {
						f[k] = v
					}
				}
			}
			if len(f) > 0 {
				out = append(out, observed("antivirus", "microsoft_defender", "host", "components_detected", f))
			}
		}
	}
	f := map[string]string{}
	for _, q := range []struct{ domain, key, fact string }{
		{"com.apple.SoftwareUpdate", "AutomaticCheckEnabled", "automatic_check_configured"}, {"com.apple.SoftwareUpdate", "AutomaticDownload", "automatic_download_configured"},
		{"com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates", "automatic_os_install_configured"}, {"com.apple.SoftwareUpdate", "CriticalUpdateInstall", "critical_update_install_configured"},
		{"com.apple.SoftwareUpdate", "ConfigDataInstall", "security_data_install_configured"}, {"com.apple.commerce", "AutoUpdate", "app_store_auto_update_configured"},
	} {
		v, e := query(ctx, r, "/usr/bin/defaults", "read", "/Library/Managed Preferences/"+q.domain, q.key)
		if e != nil {
			v, e = query(ctx, r, "/usr/bin/defaults", "read", "/Library/Preferences/"+q.domain, q.key)
		}
		if e == nil && (v == "0" || v == "1") {
			f[q.fact] = strconv.FormatBool(v == "1")
		}
	}
	if v, e := query(ctx, r, "/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "LastSuccessfulDate"); e == nil && len(v) < 128 {
		f["last_successful_check"] = v
	}
	if len(f) > 0 {
		out = append(out, observed("automatic_updates", "macos_software_update", "host", "update_preferences_observed", f))
	} else {
		out = append(out, unavailable("automatic_updates", "macos_software_update"))
	}
	// The logged-in console user's preferences, not root's defaults. No offline
	// account homes are scanned and user-provided executables are never launched.
	uid, e := query(ctx, r, "/usr/bin/stat", "-f", "%u", "/dev/console")
	if e == nil {
		n, err := strconv.ParseUint(uid, 10, 32)
		if err == nil && n >= 500 {
			f := map[string]string{"subject_uid": uid}
			for _, q := range []struct{ key, fact string }{{"askForPassword", "password_required"}, {"askForPasswordDelay", "password_delay_seconds"}, {"idleTime", "idle_seconds"}} {
				v, err := query(ctx, r, "/usr/bin/defaults", "read", "/Library/Managed Preferences/com.apple.screensaver", q.key)
				if err != nil {
					v, err = query(ctx, r, "/usr/bin/sudo", "-n", "-H", "-u", "#"+uid, "--", "/usr/bin/defaults", "-currentHost", "read", "com.apple.screensaver", q.key)
				}
				if err != nil {
					v, err = query(ctx, r, "/usr/bin/sudo", "-n", "-H", "-u", "#"+uid, "--", "/usr/bin/defaults", "read", "com.apple.screensaver", q.key)
				}
				if err == nil && regexp.MustCompile(`^[0-9]+$`).MatchString(v) && len(v) <= 10 {
					if q.key == "askForPassword" {
						if v != "0" && v != "1" {
							continue
						}
						f[q.fact] = strconv.FormatBool(v == "1")
					} else {
						f[q.fact] = v
					}
				}
			}
			delete(f, "subject_uid") // scope carries identity; reserved provenance field is not supplied as a fact.
			if len(f) > 0 {
				out = append(out, observed("screen_lock", "macos_screensaver", "uid:"+uid, "user_preferences_observed", f))
			} else {
				out = append(out, unavailable("screen_lock", "macos_screensaver"))
			}
		}
	}
	return out
}
func plistJSON(ctx context.Context, r Runner, b []byte) (map[string]any, error) {
	out, e := r.Run(ctx, "/usr/bin/plutil", []string{"-convert", "json", "-o", "-", "--", "-"}, b)
	if e != nil {
		return nil, e
	}
	var m map[string]any
	e = json.Unmarshal(out, &m)
	return m, e
}
