package posture

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
)

func processes(s System) (map[string]int, bool) {
	paths, e := s.Glob("/proc/[0-9]*/comm")
	if e != nil {
		return nil, false
	}
	names := map[string]int{}
	complete := true
	for _, p := range paths {
		b, e := s.Read(p)
		if e != nil {
			complete = false
			continue
		}
		names[strings.TrimSpace(string(b))]++
	}
	return names, complete
}
func Antivirus(ctx context.Context, s System) []Observation {
	var out []Observation
	o := observation("antivirus", "microsoft_defender", "host")
	raw, e := s.Run(ctx, "mdatp", "health", "--output", "json")
	if e == nil {
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil || m == nil {
			o.Reason = "invalid_defender_health"
		} else {
			for _, k := range []string{"healthy", "licensed", "real_time_protection_enabled", "real_time_protection_available", "passive_mode_enabled", "definitions_status", "definitions_updated", "definitions_version", "app_version", "engine_version"} {
				if v, ok := m[k]; ok {
					var str string
					var b bool
					if json.Unmarshal(v, &str) == nil && len(str) <= 256 {
						o.Facts[k] = str
					} else if json.Unmarshal(v, &b) == nil {
						o.Facts[k] = strconv.FormatBool(b)
					}
				}
			}
			if _, ok := o.Facts["healthy"]; ok {
				o.Status = "observed"
				o.Reason = "vendor_health_queried"
			} else {
				o.Reason = "missing_defender_health_fields"
			}
		}
	} else {
		o.Reason = "defender_unavailable_or_query_denied"
	}
	out = append(out, o)
	procs, complete := processes(s)
	o = observation("antivirus", "clamav", "host")
	found := false
	serviceQueriesComplete := true
	for _, u := range []string{"clamav-daemon.service", "clamd@scan.service", "clamav-freshclam.service", "freshclam.service", "clamav-clamonacc.service", "clamonacc.service"} {
		state := unit(ctx, s, u)
		if state == nil {
			serviceQueriesComplete = false
		}
		if state != nil && state["LoadState"] == "loaded" {
			found = true
			key := strings.ReplaceAll(strings.ReplaceAll(strings.TrimSuffix(u, ".service"), "-", "_"), "@", "_")
			o.Facts[key+"_state"] = state["ActiveState"]
		}
	}
	if procs["clamd"] > 0 {
		found = true
		o.Facts["clamd_process_present"] = "true"
	} else if complete {
		o.Facts["clamd_process_present"] = "false"
	}
	if procs["clamonacc"] > 0 {
		found = true
		o.Facts["clamonacc_process_present"] = "true"
	} else if complete {
		o.Facts["clamonacc_process_present"] = "false"
	}
	for _, p := range []string{"/etc/clamav/clamd.conf", "/etc/clamd.d/scan.conf"} {
		if b, e := s.Read(p); e == nil {
			found = true
			includes, excludes := 0, 0
			for _, l := range strings.Split(string(b), "\n") {
				f := strings.Fields(l)
				if len(f) < 2 || strings.HasPrefix(f[0], "#") {
					continue
				}
				switch f[0] {
				case "OnAccessIncludePath":
					includes++
				case "OnAccessExcludePath":
					excludes++
				case "OnAccessPrevention":
					boolFact(&o, "on_access_prevention_configured", f[1])
				}
			}
			o.Facts["on_access_include_entries"] = strconv.Itoa(includes)
			o.Facts["on_access_exclude_entries"] = strconv.Itoa(excludes)
			break
		}
	}
	for _, p := range []string{"/var/lib/clamav/daily.cvd", "/var/lib/clamav/daily.cld", "/var/lib/clamav/main.cvd", "/var/lib/clamav/main.cld"} {
		// sigtool reads metadata, without invoking scans or downloads. Emit each DB
		// separately; a newer main DB must not hide stale daily definitions.
		raw, e := query(ctx, s, "sigtool", "--info", p)
		if e != nil {
			continue
		}
		found = true
		db := observation("antivirus", "clamav_signatures", p)
		db.Status = "observed"
		db.Reason = "signature_metadata_queried"
		for _, l := range strings.Split(raw, "\n") {
			k, v, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch k {
			case "Version":
				db.Facts["version"] = v
			case "Build time":
				db.Facts["built_at"] = v
				if t, ok := parseTime(v); ok {
					age := s.Now().Sub(t).Seconds()
					if age >= 0 {
						db.Facts["age_seconds"] = strconv.FormatInt(int64(age), 10)
					} else {
						db.Status = "unknown"
						db.Reason = "signature_time_in_future"
					}
				}
			}
		}
		out = append(out, db)
	}
	if found {
		o.Status = "observed"
		o.Reason = "components_detected"
	} else if complete && serviceQueriesComplete {
		o.Status = "not_detected"
		o.Reason = "no_supported_clamav_components_detected"
	} else {
		o.Status = "unknown"
		o.Reason = "clamav_inventory_incomplete"
	}
	out = append(out, o)
	for _, v := range []struct{ provider, unit, kind string }{
		{"sophos", "sophos-spl.service", "endpoint_protection"}, {"sophos_legacy", "sav-protect.service", "antivirus"},
		{"crowdstrike", "falcon-sensor.service", "edr"}, {"sentinelone", "sentinelone.service", "endpoint_protection"}, {"eset", "efs.service", "antivirus"},
	} {
		o := observation("antivirus", v.provider, "host")
		state := unit(ctx, s, v.unit)
		if state != nil && state["LoadState"] == "loaded" {
			o.Status = "observed"
			o.Reason = "service_detected"
			o.Facts["service_state"] = state["ActiveState"]
			o.Facts["product_category"] = v.kind
		} else if state != nil && state["LoadState"] == "not-found" {
			o.Status = "not_detected"
			o.Reason = "supported_service_not_detected"
		} else {
			o.Status = "unknown"
			o.Reason = "service_state_unavailable"
		}
		out = append(out, o)
	}
	return out
}
