package posture

import (
	"encoding/xml"
	"math"
	"path/filepath"
	"strconv"
	"strings"
)

// Read installed KConfig schema defaults, rather than assuming the defaults of
// a different Plasma release. Ignore code-generated/complex defaults.
func kdeDefaults(s System) map[string]string {
	type entry struct {
		Key     string `xml:"key,attr"`
		Default string `xml:"default"`
	}
	var schema struct {
		Groups []struct {
			Name    string  `xml:"name,attr"`
			Entries []entry `xml:"entry"`
		} `xml:"group"`
	}
	for _, p := range []string{"/usr/share/config.kcfg/kscreenlockersettings.kcfg", "/usr/share/kconfig.kcfg/kscreenlockersettings.kcfg"} {
		raw, e := s.Read(p)
		if e != nil || xml.Unmarshal(raw, &schema) != nil {
			continue
		}
		m := map[string]string{}
		for _, g := range schema.Groups {
			if g.Name != "Daemon" {
				continue
			}
			for _, e := range g.Entries {
				v := strings.TrimSpace(e.Default)
				if len(v) <= 32 && v != "" {
					m[e.Key] = v
				}
			}
		}
		return m
	}
	return nil
}
func fractionalSeconds(o *Observation, key, v string, mult float64) bool {
	n, e := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if e != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n*mult > 31536000 {
		return false
	}
	o.Facts[key] = strconv.FormatFloat(n*mult, 'f', -1, 64)
	return true
}
func ownProcess(s System, name string) bool {
	paths, e := s.Glob("/proc/[0-9]*/comm")
	if e != nil {
		return false
	}
	for _, p := range paths {
		b, e := s.Read(p)
		if e != nil || strings.TrimSpace(string(b)) != name {
			continue
		}
		st, e := s.Read(filepath.Join(filepath.Dir(p), "status"))
		if e != nil {
			continue
		}
		for _, line := range strings.Split(string(st), "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && f[0] == "Uid:" && f[1] == strconv.Itoa(s.UID()) && f[2] == strconv.Itoa(s.UID()) {
				return true
			}
		}
	}
	return false
}
func clockDuration(v string) (int64, bool) {
	f := strings.Split(v, ":")
	if len(f) != 3 {
		return 0, false
	}
	a, ao := number(f[0])
	b, bo := number(f[1])
	c, co := number(f[2])
	vsec := a*3600 + b*60 + c
	return vsec, ao && bo && co && b < 60 && c < 60 && vsec <= 31536000
}
func xscreensaver(s System, scope string) (Observation, bool) {
	o := observation("screen_lock", "xscreensaver", scope)
	if !ownProcess(s, "xscreensaver") {
		return o, false
	}
	home := s.Env("HOME")
	if !filepath.IsAbs(home) {
		return failed(o, "home_directory_unavailable"), true
	}
	b, e := s.Read(filepath.Join(home, ".xscreensaver"))
	if e != nil {
		return failed(o, "xscreensaver_configuration_unavailable"), true
	}
	vals := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	valid := boolFact(&o, "lock_enabled", vals["lock"])
	for k, fact := range map[string]string{"timeout": "idle_seconds", "lockTimeout": "lock_delay_seconds"} {
		if n, ok := clockDuration(vals[k]); ok {
			o.Facts[fact] = strconv.FormatInt(n, 10)
		} else {
			valid = false
		}
	}
	switch vals["mode"] {
	case "off", "blank", "one", "random", "random-same":
		o.Facts["mode"] = vals["mode"]
	default:
		valid = false
	}
	o.Facts["process_present"] = "true"
	o.Facts["effective_protection"] = "not_evaluated"
	if valid {
		o.Status = "observed"
		o.Reason = "configuration_file_runtime_overrides_unverified"
	} else {
		o.Reason = "xscreensaver_defaults_or_configuration_unverified"
	}
	return o, true
}
