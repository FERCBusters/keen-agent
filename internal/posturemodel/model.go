package posturemodel

import (
	"errors"
	"regexp"
	"sort"
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

// Coverage records what one collector run attempted, so KEEN can tell a check
// that was not measured from one that was never attempted.
type Coverage struct {
	Version     int      `json:"version"`
	Kind        string   `json:"kind"`
	Collector   string   `json:"collector"`
	RunID       string   `json:"run_id"`
	Attempted   []string `json:"checks_attempted"`
	Observed    []string `json:"checks_observed"`
	Unavailable []string `json:"probes_unavailable"`
}

var safeRun = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// CoverageOf summarises all observations of a run, including failed probes.
func CoverageOf(collector, runID string, all []Observation) Coverage {
	attempted, observed, unavailable := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, o := range all {
		if o.Validate() != nil {
			continue
		}
		attempted[o.Check] = true
		if o.Status == "observed" {
			observed[o.Check] = true
		} else {
			unavailable[o.Check+"/"+o.Provider] = true
		}
	}
	return Coverage{1, "coverage", collector, runID, keys(attempted), keys(observed), keys(unavailable)}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (c Coverage) Validate() error {
	if c.Version != 1 || c.Kind != "coverage" || !safeKey.MatchString(c.Collector) || !safeRun.MatchString(c.RunID) {
		return errors.New("invalid coverage record")
	}
	for _, list := range [][]string{c.Attempted, c.Observed, c.Unavailable} {
		if len(list) > 64 {
			return errors.New("coverage list too long")
		}
		for _, v := range list {
			if len(v) > 129 || !regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}(/[a-z][a-z0-9_.]{0,63})?$`).MatchString(v) {
				return errors.New("invalid coverage entry")
			}
		}
	}
	return nil
}
