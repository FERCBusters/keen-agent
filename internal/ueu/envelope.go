package ueu

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// SpecVersion names KEEN's profile of the draft UEU specification.
const SpecVersion = "0.1-keen"

// PrivacyProfile names the minimisation rules producers apply at source.
const PrivacyProfile = "keen-default-1"

// TimeFormat is the profile's timestamp form: UTC with milliseconds.
const TimeFormat = "2006-01-02T15:04:05.000Z"

// Mode is an organisation's choice of what server log collection sends.
type Mode string

const (
	ModeEvents         Mode = "events"
	ModeEventsAndLines Mode = "events_with_lines"
	ModeAllLines       Mode = "all_lines"
)

func (m Mode) rank() int {
	switch m {
	case ModeEvents:
		return 1
	case ModeEventsAndLines:
		return 2
	case ModeAllLines:
		return 3
	}
	return 0
}

// ParseMode accepts a configured mode; empty means the default, events.
func ParseMode(v string) (Mode, error) {
	if v == "" {
		return ModeEvents, nil
	}
	m := Mode(v)
	if m.rank() == 0 {
		return "", fmt.Errorf("evidence_mode must be events, events_with_lines or all_lines")
	}
	return m, nil
}

// Within reports whether m is allowed under the ceiling KEEN set.
func (m Mode) Within(ceiling Mode) bool { return m.rank() <= ceiling.rank() }

// IncludesLines reports whether recognised events carry their source line.
func (m Mode) IncludesLines() bool { return m.rank() >= 2 }

// Subject pseudonymises local account identifiers. Pairwise subjects use a
// key that never leaves the device, so they differ between devices; public
// subjects use a key KEEN issues to every agent, so they match across devices.
type Subject struct {
	Type string
	Key  []byte
}

// NewPairwiseKey returns fresh key material for a pairwise subject.
func NewPairwiseKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

// Pseudonym returns hmac-sha256:<hex> for a kind of identifier and its value.
func (s Subject) Pseudonym(kind, raw string) (string, error) {
	if (s.Type != "pairwise" && s.Type != "public") || len(s.Key) < 32 {
		return "", errors.New("UEU_PRIVACY_POLICY_FAILED: no subject key")
	}
	m := hmac.New(sha256.New, s.Key)
	m.Write([]byte("keen-ueu-subject-v1\x00" + kind + "\x00" + raw))
	return "hmac-sha256:" + hex.EncodeToString(m.Sum(nil)), nil
}

// Producer holds the identity every envelope from one agent carries.
type Producer struct {
	Catalogue          *Catalogue
	ApplicationID      string
	ApplicationVersion string
	InstanceID         string
	AssetType          string
	Platform           string
	Subject            Subject
}

// Observation is a measured state from a posture collector.
type Observation struct {
	Check, Provider, Scope, Status, Reason string
	Facts                                  map[string]string
	ObservedAt                             time.Time
	SubjectKind, SubjectValue              string
	Method                                 string
	ValidFor                               time.Duration
}

// Event is something that happened, usually recognised in a log line.
type Event struct {
	Type, Component, Action, Outcome, Reason string
	Time                                     time.Time
	Attributes                               map[string]string
	SubjectKind, SubjectValue                string
	SourceRecord                             string
	IncludePayload                           bool
	Mode                                     Mode
	SupportingRecord                         string
}

var outcomes = map[string]bool{"observed": true, "unknown": true, "success": true, "failure": true, "info": true}

func (p Producer) base(eventType string, t time.Time, component, action, outcome, reason string) (map[string]any, EventType, error) {
	spec, err := p.Catalogue.Type(eventType)
	if err != nil {
		return nil, spec, err
	}
	if p.InstanceID == "" || p.ApplicationID == "" {
		return nil, spec, errors.New("UEU_CONFIGURATION_INVALID: producer identity missing")
	}
	if !outcomes[outcome] {
		return nil, spec, fmt.Errorf("UEU_SCHEMA_VALIDATION_FAILED: outcome %q", outcome)
	}
	for _, s := range []string{component, action, reason} {
		if len(s) > 256 || !utf8.ValidString(s) {
			return nil, spec, errors.New("UEU_SCHEMA_VALIDATION_FAILED: event text too long")
		}
	}
	// A record dated ahead of this clock (a misconfigured source or host
	// clock) would be refused by the receiver and stall delivery; it is
	// recorded at the time it was collected instead.
	if now := time.Now(); t.After(now.Add(time.Minute)) {
		t = now
	}
	id, err := NewEvidenceID(t)
	if err != nil {
		return nil, spec, err
	}
	env := map[string]any{
		"ueu_spec_version": SpecVersion,
		"evidence_id":      id,
		"event_type":       eventType,
		"catalogue":        map[string]any{"id": p.Catalogue.Ref.ID, "version": p.Catalogue.Ref.Version},
		"event_time":       t.UTC().Format(TimeFormat),
		"source": map[string]any{
			"application_id":      p.ApplicationID,
			"application_version": p.ApplicationVersion,
			"component":           component,
			"instance_id":         p.InstanceID,
		},
		"asset": map[string]any{"asset_type": p.AssetType, "platform": p.Platform, "identifier": p.InstanceID},
		"event": map[string]any{"action": action, "object_type": spec.ObjectType, "outcome": outcome, "reason_code": reason},
		"privacy": map[string]any{
			"profile":                PrivacyProfile,
			"personal_data_included": false,
			"transformations":        []any{},
		},
		"mappings": []any{},
	}
	return env, spec, nil
}

func (p Producer) subject(env map[string]any, spec EventType, kind, value string) error {
	if value == "" {
		if spec.Subject == "required" {
			return errors.New("UEU_SCHEMA_VALIDATION_FAILED: subject required")
		}
		return nil
	}
	if spec.Subject == "forbidden" {
		return errors.New("UEU_PROHIBITED_FIELD_DETECTED: subject")
	}
	id, err := p.Subject.Pseudonym(kind, value)
	if err != nil {
		return err
	}
	env["subject"] = map[string]any{"identifier_type": p.Subject.Type, "identifier": id}
	addTransformation(env, "subject-pseudonymised")
	return nil
}

func addTransformation(env map[string]any, v string) {
	privacy := env["privacy"].(map[string]any)
	privacy["transformations"] = append(privacy["transformations"].([]any), v)
}

// MaxTransformations bounds privacy.transformations.
const MaxTransformations = 64

// recordRejections names each removed field and why. A name that is not a
// valid field name is itself untrusted text, so it is recorded as "unnamed".
func recordRejections(env map[string]any, rejected []Rejection) {
	for _, r := range rejected {
		if len(env["privacy"].(map[string]any)["transformations"].([]any)) == MaxTransformations-1 {
			addTransformation(env, "removed:further_fields:truncated")
			return
		}
		field := r.Field
		if !fieldName.MatchString(field) {
			field = "unnamed"
		}
		addTransformation(env, "removed:"+field+":"+r.Reason)
	}
}

// Observe builds an observation envelope. Unknown or failed probes are not
// evidence: only measured states (status observed) become envelopes.
func (p Producer) Observe(o Observation) (map[string]any, error) {
	if o.Status != "observed" {
		return nil, errors.New("only observed states become evidence")
	}
	if o.ObservedAt.IsZero() {
		return nil, errors.New("UEU_SCHEMA_VALIDATION_FAILED: observation time missing")
	}
	env, spec, err := p.base("endpoint."+o.Check+".observed", o.ObservedAt, o.Provider, "observe", "observed", o.Reason)
	if err != nil {
		return nil, err
	}
	if spec.Class != "observation" {
		return nil, errors.New("UEU_EVENT_TYPE_UNKNOWN: not an observation")
	}
	if o.Scope == "" || len(o.Scope) > 256 {
		return nil, errors.New("UEU_SCHEMA_VALIDATION_FAILED: observation scope")
	}
	facts, rejected := Convert(spec.Facts, spec.AdditionalFacts, spec.Prohibited, o.Facts)
	validFor := int64(o.ValidFor / time.Second)
	if validFor <= 0 {
		validFor = 86400
	}
	method := o.Method
	if method == "" {
		method = "native_query"
	}
	env["observation"] = map[string]any{"method": method, "scope": o.Scope, "valid_for_seconds": validFor, "facts": facts}
	env["evidence"] = map[string]any{"payload_included": false}
	if err = p.subject(env, spec, o.SubjectKind, o.SubjectValue); err != nil {
		return nil, err
	}
	recordRejections(env, rejected)
	return env, nil
}

// Emit builds an event envelope. The source record itself is included only
// when the event type allows it and the organisation's mode asks for it.
func (p Producer) Emit(e Event) (map[string]any, error) {
	env, spec, err := p.base(e.Type, e.Time, e.Component, e.Action, e.Outcome, e.Reason)
	if err != nil {
		return nil, err
	}
	if spec.Class != "event" {
		return nil, errors.New("UEU_EVENT_TYPE_UNKNOWN: not an event")
	}
	attributes, rejected := Convert(spec.Attributes, spec.AdditionalAttributes, spec.Prohibited, e.Attributes)
	env["attributes"] = attributes
	evidence := map[string]any{"payload_included": false}
	if e.Mode != "" {
		evidence["collection_mode"] = string(e.Mode)
	}
	if e.SourceRecord != "" {
		sum := sha256.Sum256([]byte(e.SourceRecord))
		evidence["payload_hash"] = "sha256:" + hex.EncodeToString(sum[:])
		include := e.IncludePayload || spec.Payload == "required"
		if include && spec.Payload == "forbidden" {
			return nil, errors.New("UEU_PROHIBITED_FIELD_DETECTED: payload")
		}
		if include {
			if !utf8.ValidString(e.SourceRecord) || len(e.SourceRecord) > 60000 {
				return nil, errors.New("UEU_SCHEMA_VALIDATION_FAILED: payload")
			}
			evidence["payload_included"] = true
			evidence["payload"] = e.SourceRecord
			// A source record is redacted, not minimised: it can name
			// people, addresses or hosts.
			env["privacy"].(map[string]any)["personal_data_included"] = true
		}
	} else if spec.Payload == "required" {
		return nil, errors.New("UEU_SCHEMA_VALIDATION_FAILED: payload required")
	}
	if e.SupportingRecord != "" {
		if len(e.SupportingRecord) > 512 || !utf8.ValidString(e.SupportingRecord) {
			return nil, errors.New("UEU_SCHEMA_VALIDATION_FAILED: supporting record reference")
		}
		evidence["supporting_record_reference"] = e.SupportingRecord
	}
	env["evidence"] = evidence
	if err = p.subject(env, spec, e.SubjectKind, e.SubjectValue); err != nil {
		return nil, err
	}
	recordRejections(env, rejected)
	return env, nil
}

// LocalAccount classifies a posture scope that names a local account, so it
// can be sent as a pseudonymous subject. It returns the account kind, its
// value and the scope to report instead.
func LocalAccount(scope string) (kind, value, replacement string) {
	switch {
	case strings.HasPrefix(scope, "uid:"):
		return "unix_uid", strings.TrimPrefix(scope, "uid:"), "user"
	case strings.HasPrefix(scope, "S-1-5-21-"), strings.HasPrefix(scope, "S-1-12-1-"):
		return "windows_sid", scope, "user"
	}
	return "", "", scope
}
