package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"keen-agent/internal/posture"
	"keen-agent/internal/posturemodel"
	"os"
	"strconv"
	"time"
)

func runPosture(command string, diagnostics bool) error {
	session := command == "posture-session"
	if session && os.Getuid() == 0 {
		return errors.New("posture-session must run as the graphical desktop user, not root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	sys := posture.Local{Session: session}
	var observations []posture.Observation
	if session {
		observations = posture.Desktop(ctx, sys)
	} else {
		observations = posture.Host(ctx, sys)
	}
	if !diagnostics {
		observations = posturemodel.Evidence(observations)
	}
	return posture.Emit(os.Stdout, observations)
}

// Only journal-attested unit/UID metadata controls authority. JSON and the
// configurable source name cannot grant a desktop process host authority.
func normalizePosture(e *Event) error {
	uid, err := strconv.ParseUint(e.Fields["_UID"], 10, 32)
	if err != nil {
		return errors.New("missing journal UID")
	}
	host := uid == 0 && e.Fields["_SYSTEMD_UNIT"] == "keen-posture-host.service"
	desktop := uid != 0 && e.Fields["_SYSTEMD_USER_UNIT"] == "keen-posture-session.service"
	if e.Fields["_TRANSPORT"] != "stdout" || (!host && !desktop) {
		return errors.New("untrusted posture journal origin")
	}
	var o posture.Observation
	decoder := json.NewDecoder(bytes.NewBufferString(e.Raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&o); err != nil {
		return errors.New("invalid posture JSON")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("trailing posture JSON")
	}
	if err := o.Validate(); err != nil {
		return err
	}
	if desktop && o.Check != "screen_lock" {
		return errors.New("desktop cannot report host posture")
	}
	if host && o.Check == "screen_lock" && o.Provider != "qubes" {
		return errors.New("host cannot report user screen lock")
	}
	e.Action = "posture." + o.Check
	e.Outcome = "info"
	e.Severity = 3
	e.Actor = strconv.FormatUint(uid, 10)
	e.Summary = fmt.Sprintf("%s (%s, %s): %s; %s", o.Check, o.Provider, o.Scope, o.Status, o.Reason)
	e.Fields["posture.schema_version"] = "1"
	e.Fields["posture.check"] = o.Check
	e.Fields["posture.provider"] = o.Provider
	e.Fields["posture.scope"] = o.Scope
	e.Fields["posture.status"] = o.Status
	e.Fields["posture.reason"] = o.Reason
	authority := "host_root"
	if desktop {
		authority = "user_session"
	}
	e.Fields["posture.authority"] = authority
	e.Fields["posture.subject_uid"] = strconv.FormatUint(uid, 10)
	e.Fields["posture.observed_at"] = e.Timestamp.UTC().Format(time.RFC3339Nano)
	for k, v := range o.Facts {
		e.Fields["posture."+k] = v
	}
	return nil
}
