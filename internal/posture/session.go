package posture

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
)

type session struct {
	ID      string `json:"id"`
	UID     string `json:"uid"`
	Type    string `json:"type"`
	Desktop string `json:"desktop"`
	Active  string `json:"active"`
	Locked  string `json:"locked_hint"`
}

func sessions(ctx context.Context, s System) ([]session, bool) {
	raw, e := query(ctx, s, "loginctl", "list-sessions", "--no-legend", "--no-pager")
	if e != nil {
		return nil, false
	}
	var out []session
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || len(out) >= 32 {
			return out, false
		}
		if !safeSessionID(f[0]) {
			return out, false
		}
		b, e := query(ctx, s, "loginctl", "show-session", f[0], "--no-pager", "--property=User,Type,Class,Desktop,Active,LockedHint,Remote")
		if e != nil {
			return out, false
		}
		p := properties(b)
		if p["Type"] != "x11" && p["Type"] != "wayland" {
			continue
		}
		if p["Class"] != "user" && p["Class"] != "user-early" {
			continue
		}
		out = append(out, session{f[0], p["User"], p["Type"], p["Desktop"], p["Active"], p["LockedHint"]})
	}
	return out, true
}
func safeSessionID(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
func Sessions(ctx context.Context, s System) Observation {
	o := observation("session_inventory", "logind", "host")
	ss, ok := sessions(ctx, s)
	if !ok {
		return failed(o, "session_inventory_incomplete")
	}
	b, _ := json.Marshal(ss)
	if len(b) > 1024 {
		return failed(o, "session_inventory_too_large")
	}
	o.Status = "observed"
	o.Reason = "graphical_sessions_enumerated"
	o.Facts["graphical_sessions"] = string(b)
	o.Facts["graphical_session_count"] = strconv.Itoa(len(ss))
	return o
}
func Desktop(ctx context.Context, s System) []Observation {
	if IsQubes(s) {
		return []Observation{QubesContext("session")}
	}
	o := observation("screen_lock", "desktop", "session")
	ss, complete := sessions(ctx, s)
	var mine []session
	for _, v := range ss {
		if v.UID == strconv.Itoa(s.UID()) {
			mine = append(mine, v)
		}
	}
	if !complete {
		return []Observation{failed(o, "session_inventory_incomplete")}
	}
	if len(mine) == 0 {
		o.Status = "not_applicable"
		o.Reason = "no_graphical_session"
		return []Observation{o}
	}
	// A per-user bus/settings store cannot unambiguously attest multiple sessions.
	if len(mine) != 1 {
		return []Observation{failed(o, "multiple_graphical_sessions_for_uid")}
	}
	current := mine[0]
	o.Scope = "session:" + current.ID
	o.Facts["session_id"] = current.ID
	o.Facts["session_type"] = current.Type
	o.Facts["session_active"] = current.Active
	o.Facts["locked_hint"] = current.Locked
	desktop := current.Desktop
	if desktop == "" {
		desktop = s.Env("XDG_CURRENT_DESKTOP")
		o.Facts["desktop_identification"] = "environment_fallback"
	} else {
		o.Facts["desktop_identification"] = "logind"
	}
	desktop = strings.ToLower(desktop)
	switch {
	case strings.Contains(desktop, "cinnamon"):
		o.Provider = "cinnamon"
		gsettingsLock(ctx, s, &o, "org.cinnamon.desktop", "org.cinnamon.ScreenSaver", true)
	case strings.Contains(desktop, "mate"):
		o.Provider = "mate"
		mateLock(ctx, s, &o)
	case strings.Contains(desktop, "gnome") || desktop == "ubuntu" || strings.Contains(desktop, "unity"):
		o.Provider = "gnome"
		gsettingsLock(ctx, s, &o, "org.gnome.desktop", "org.gnome.ScreenSaver", false)
	case strings.Contains(desktop, "xfce"):
		o.Provider = "xfce"
		xfceLock(ctx, s, &o)
	case strings.Contains(desktop, "kde") || strings.Contains(desktop, "plasma"):
		o.Provider = "kde"
		kdeLock(ctx, s, &o)
	default:
		o.Status = "unsupported"
		o.Reason = "desktop_or_locker_not_supported"
	}
	out := []Observation{o}
	if extra, ok := xscreensaver(s, o.Scope); ok {
		out = append(out, extra)
	}
	return out
}

// GetNameOwner has no activation side effect (unlike calling a locker method).
func busOwner(ctx context.Context, s System, name string) bool {
	b, e := query(ctx, s, "busctl", "--user", "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", "s", name)
	return e == nil && strings.HasPrefix(b, `s ":`)
}
func getSetting(ctx context.Context, s System, schema, key string) (string, bool) {
	v, e := query(ctx, s, "gsettings", "get", schema, key)
	return v, e == nil
}
func gsettingsLock(ctx context.Context, s System, o *Observation, prefix, bus string, idleActivation bool) {
	enabled, e := getSetting(ctx, s, prefix+".screensaver", "lock-enabled")
	idle, i := getSetting(ctx, s, prefix+".session", "idle-delay")
	delay, d := getSetting(ctx, s, prefix+".screensaver", "lock-delay")
	valid := e && i && d
	if !boolFact(o, "lock_enabled", enabled) {
		valid = false
	}
	if !setNumber(o, "idle_seconds", idle, 1) {
		valid = false
	}
	if !setNumber(o, "lock_delay_seconds", delay, 1) {
		valid = false
	}
	if idleActivation {
		v, ok := getSetting(ctx, s, prefix+".screensaver", "idle-activation-enabled")
		if !ok || !boolFact(o, "idle_activation_enabled", v) {
			valid = false
		}
	}
	// GNOME's global lockdown can override the screensaver preference.
	if prefix == "org.gnome.desktop" {
		v, ok := getSetting(ctx, s, prefix+".lockdown", "disable-lock-screen")
		if !ok || !boolFact(o, "locking_disabled_by_policy", v) {
			valid = false
		}
	}
	owner := busOwner(ctx, s, bus)
	o.Facts["locker_bus_owned"] = strconv.FormatBool(owner)
	if valid {
		o.Status = "observed"
		o.Reason = "effective_user_settings_queried"
		deriveAutoLock(o)
	} else {
		o.Reason = "desktop_settings_incomplete"
	}
	if !owner {
		o.Status = "unknown"
		o.Reason = "locker_bus_owner_unverified"
		delete(o.Facts, "automatic_lock_configured")
	}
	// Writable does not change the result; it identifies user-changeable policy.
	if v, e := query(ctx, s, "gsettings", "writable", prefix+".screensaver", "lock-enabled"); e == nil {
		boolFact(o, "lock_setting_user_writable", v)
	}
}
func deriveAutoLock(o *Observation) {
	enabled := o.Facts["lock_enabled"] == "true" && o.Facts["idle_seconds"] != "0" && o.Facts["idle_seconds"] != "" && o.Facts["locking_disabled_by_policy"] != "true" && o.Facts["idle_activation_enabled"] != "false"
	o.Facts["automatic_lock_configured"] = strconv.FormatBool(enabled)
	if enabled {
		a, aok := number(o.Facts["idle_seconds"])
		b, bok := number(o.Facts["lock_delay_seconds"])
		if aok && bok {
			o.Facts["total_idle_to_lock_seconds"] = strconv.FormatInt(a+b, 10)
		}
	}
}
func mateLock(ctx context.Context, s System, o *Observation) {
	valid := true
	for _, q := range []struct {
		schema, key, fact string
		mult              int64
	}{
		{"org.mate.screensaver", "lock-enabled", "lock_enabled", 0}, {"org.mate.screensaver", "idle-activation-enabled", "idle_activation_enabled", 0},
		{"org.mate.session", "idle-delay", "idle_seconds", 60}, {"org.mate.screensaver", "lock-delay", "lock_delay_seconds", 60},
	} {
		v, ok := getSetting(ctx, s, q.schema, q.key)
		if !ok {
			valid = false
			continue
		}
		if q.mult == 0 {
			if !boolFact(o, q.fact, v) {
				valid = false
			}
		} else if !setNumber(o, q.fact, v, q.mult) {
			valid = false
		}
	}
	owner := busOwner(ctx, s, "org.mate.ScreenSaver")
	o.Facts["locker_bus_owned"] = strconv.FormatBool(owner)
	if valid && owner {
		o.Status = "observed"
		o.Reason = "effective_user_settings_queried"
		deriveAutoLock(o)
	} else {
		o.Reason = "desktop_settings_or_locker_unverified"
	}
}
func xfceLock(ctx context.Context, s System, o *Observation) {
	valid := true
	for _, q := range []struct {
		key, fact string
		mult      int64
	}{
		{"/lock/enabled", "lock_enabled", 0}, {"/saver/enabled", "saver_enabled", 0}, {"/saver/idle-activation/enabled", "idle_activation_enabled", 0}, {"/lock/saver-activation/enabled", "lock_with_saver", 0},
		{"/saver/idle-activation/delay", "idle_seconds", 60}, {"/lock/saver-activation/delay", "lock_delay_seconds", 60},
	} {
		v, e := query(ctx, s, "xfconf-query", "--channel", "xfce4-screensaver", "--property", q.key)
		if e != nil {
			valid = false
			continue
		}
		if q.mult == 0 {
			if !boolFact(o, q.fact, v) {
				valid = false
			}
		} else if !setNumber(o, q.fact, v, q.mult) {
			valid = false
		}
	}
	// Missing Xfconf properties mean defaults, but defaults vary by version. Do
	// not infer them from another desktop/version or read stale XML as effective.
	owner := busOwner(ctx, s, "org.xfce.ScreenSaver")
	o.Facts["locker_bus_owned"] = strconv.FormatBool(owner)
	if valid && owner {
		o.Status = "observed"
		o.Reason = "effective_user_settings_queried"
		deriveAutoLock(o)
		if o.Facts["saver_enabled"] == "false" || o.Facts["lock_with_saver"] == "false" {
			o.Facts["automatic_lock_configured"] = "false"
			delete(o.Facts, "total_idle_to_lock_seconds")
		}
	} else {
		o.Reason = "xfconf_defaults_or_locker_unverified"
	}
	if v, e := query(ctx, s, "xfconf-query", "--channel", "xfce4-screensaver", "--property", "/lock/sleep-activation"); e == nil {
		boolFact(o, "screensaver_lock_on_suspend_configured", v)
	}
	if v, e := query(ctx, s, "xfconf-query", "--channel", "xfce4-screensaver", "--property", "/saver/fullscreen-inhibit"); e == nil {
		boolFact(o, "fullscreen_inhibits_saver", v)
	}
	if v, e := query(ctx, s, "xfconf-query", "--channel", "xfce4-power-manager", "--property", "/xfce4-power-manager/lock-screen-suspend-hibernate"); e == nil {
		boolFact(o, "lock_on_suspend_configured", v)
	}
}
func kdeLock(ctx context.Context, s System, o *Observation) {
	// KConfig resolves config layering; parsing just ~/.config would miss globals
	// and immutable keys. An explicit sentinel avoids guessing compiled defaults.
	tool := "kreadconfig6"
	_, e := query(ctx, s, tool, "--file", "kscreenlockerrc", "--group", "Daemon", "--key", "Autolock", "--default", "__KEEN_UNSET__")
	if e != nil {
		tool = "kreadconfig5"
	}
	defaults := kdeDefaults(s)
	valid := true
	for _, q := range []struct {
		key, fact string
		mult      int64
	}{{"Autolock", "lock_enabled", 0}, {"Timeout", "idle_seconds", 60}, {"LockGrace", "lock_delay_seconds", 1}, {"LockOnResume", "lock_on_resume_configured", 0}, {"RequirePassword", "password_required_configured", 0}} {
		v, e := query(ctx, s, tool, "--file", "kscreenlockerrc", "--group", "Daemon", "--key", q.key, "--default", "__KEEN_UNSET__")
		if e == nil && v == "__KEEN_UNSET__" && defaults[q.key] != "" {
			v = defaults[q.key]
			o.Facts["defaults_basis"] = "installed_kconfig_schema"
		}
		if e != nil || v == "__KEEN_UNSET__" {
			valid = false
			continue
		}
		if q.mult == 0 {
			if !boolFact(o, q.fact, v) {
				valid = false
			}
		} else if !fractionalSeconds(o, q.fact, v, float64(q.mult)) {
			valid = false
		}
	}
	owner := busOwner(ctx, s, "org.freedesktop.ScreenSaver")
	o.Facts["locker_bus_owned"] = strconv.FormatBool(owner)
	// Kiosk restrictions and runtime reconfiguration require more than KConfig.
	// Expose configured values without asserting effective automatic protection.
	if valid && owner {
		o.Status = "observed"
		o.Reason = "kconfig_values_runtime_policy_unverified"
		o.Facts["effective_protection"] = "not_evaluated"
	} else {
		o.Reason = "kconfig_defaults_or_locker_unverified"
	}
}
