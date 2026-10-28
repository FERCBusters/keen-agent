package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"keen-agent/internal/agentauth"
	"keen-agent/internal/posture"
	"keen-agent/internal/posturemodel"
	"os"
	"strconv"
	"strings"
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
	var all []posture.Observation
	collector := "posture_host"
	if session {
		all = posture.Desktop(ctx, sys)
		collector = "posture_session"
	} else {
		all = posture.Host(ctx, sys)
	}
	runID, err := agentauth.NewSecret()
	if err != nil {
		return err
	}
	coverage := posturemodel.CoverageOf(collector, runID[:22], all)
	observations := all
	if !diagnostics {
		observations = posturemodel.Evidence(all)
	}
	return posture.Emit(os.Stdout, observations, coverage)
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
	e.Authority = "host_root"
	if desktop {
		e.Authority = "user_session"
	}
	if strings.Contains(e.Raw, `"kind":"coverage"`) {
		var c posturemodel.Coverage
		if err := strictJSON(e.Raw, &c); err != nil {
			return errors.New("invalid posture coverage JSON")
		}
		if err := c.Validate(); err != nil {
			return err
		}
		if (desktop && c.Collector != "posture_session") || (host && c.Collector != "posture_host") {
			return errors.New("coverage collector does not match its unit")
		}
		e.Coverage = &c
		return nil
	}
	var o posture.Observation
	if err := strictJSON(e.Raw, &o); err != nil {
		return errors.New("invalid posture JSON")
	}
	if err := o.Validate(); err != nil {
		return err
	}
	if o.Status != "observed" {
		return errors.New("unmeasured posture is not evidence")
	}
	if desktop && o.Check != "screen_lock" {
		return errors.New("desktop cannot report host posture")
	}
	if host && o.Check == "screen_lock" && o.Provider != "qubes" {
		return errors.New("host cannot report user screen lock")
	}
	e.Action = "posture." + o.Check
	e.Posture = &o
	return nil
}

func strictJSON(raw string, v any) error {
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
