package posturemodel

import (
	"errors"
	"regexp"
)

type Observation struct {
	Version  int               `json:"version"`
	Check    string            `json:"check"`
	Provider string            `json:"provider"`
	Scope    string            `json:"scope"`
	Status   string            `json:"status"`
	Reason   string            `json:"reason"`
	Facts    map[string]string `json:"facts"`
}

func New(check, provider, scope string) Observation {
	return Observation{1, check, provider, scope, "unknown", "insufficient_evidence", map[string]string{}}
}

var safeKey = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

func (o Observation) Validate() error {
	if o.Version != 1 {
		return errors.New("unsupported observation version")
	}
	switch o.Check {
	case "disk_encryption", "firewall", "antivirus", "automatic_updates", "screen_lock", "session_inventory":
	default:
		return errors.New("invalid check")
	}
	switch o.Status {
	case "observed", "unknown", "unsupported", "error", "not_detected", "not_applicable":
	default:
		return errors.New("invalid status")
	}
	if !safeKey.MatchString(o.Provider) || len(o.Scope) > 512 || o.Scope == "" || len(o.Reason) > 256 || len(o.Facts) > 40 {
		return errors.New("invalid observation metadata")
	}
	total := 0
	for k, v := range o.Facts {
		switch k {
		case "schema_version", "check", "provider", "scope", "status", "reason", "authority", "subject_uid", "observed_at":
			return errors.New("reserved observation fact")
		}
		total += len(k) + len(v)
		if total > 8000 {
			return errors.New("observation facts too large")
		}
		if !safeKey.MatchString(k) || len(v) > 1024 {
			return errors.New("invalid observation fact")
		}
	}
	return nil
}

// Evidence keeps measured false/disabled values; absence and failed probes are diagnostics.
func Evidence(all []Observation) []Observation {
	out := []Observation{}
	for _, o := range all {
		if o.Status == "observed" {
			out = append(out, o)
		}
	}
	return out
}
