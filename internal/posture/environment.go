package posture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

type probeError struct {
	reason string
	err    error
}

func (e *probeError) Error() string { return e.reason }
func (e *probeError) Unwrap() error { return e.err }
func commandError(name string, err, ctxerr error, stderr string) error {
	reason := "command_failed"
	v := strings.ToLower(stderr)
	if errors.Is(ctxerr, context.DeadlineExceeded) {
		reason = "query_timed_out"
	} else if strings.Contains(v, "permission denied") || strings.Contains(v, "operation not permitted") || strings.Contains(v, "must be root") {
		reason = "permission_denied"
	} else if strings.Contains(v, "table does not exist") {
		reason = "filter_table_absent"
	}
	return &probeError{reason, fmt.Errorf("%s: %w", name, err)}
}
func FailureReason(err error) string {
	var e *probeError
	if errors.As(err, &e) {
		return e.reason
	}
	if errors.Is(err, os.ErrNotExist) {
		return "tool_not_installed"
	}
	return "query_failed"
}
func IsQubes(s System) bool {
	// Qubes guest marker, not generic Xen detection (Xen alone is not Qubes).
	if b, e := s.Read("/usr/share/qubes/marker-vm"); e == nil && len(b) <= 4096 {
		return true
	}
	if b, e := s.Read("/etc/qubes-release"); e == nil && strings.Contains(strings.ToLower(string(b)), "qubes") {
		return true
	}
	return false
}
func QubesContext(scope string) Observation {
	check := "disk_encryption"
	layer := "qubes_storage_domain"
	if scope == "session" {
		check = "screen_lock"
		layer = "qubes_gui_domain"
	}
	if scope == "network" {
		check = "firewall"
		layer = "qubes_network_domain"
	}
	o := observation(check, "qubes", scope)
	o.Status = "observed"
	o.Reason = "managed_outside_qube"
	o.Facts["environment"] = "qubes_guest"
	o.Facts["control_location"] = layer
	o.Facts["verification"] = "external_evidence_required"
	return o
}
