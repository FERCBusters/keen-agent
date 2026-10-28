package ueu

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

//go:embed catalogue/keen-2026.10.json
var keenCatalogue []byte

// Field limits shared with KEEN's validator.
const (
	MaxString     = 1024
	MaxListItems  = 64
	MaxListString = 256
	MaxFields     = 48
)

var fieldName = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

type FieldSpec struct {
	Type           string `json:"type"`
	Classification string `json:"classification,omitempty"`
}

type EventType struct {
	Class                string               `json:"class"`
	ObjectType           string               `json:"object_type"`
	Summary              string               `json:"summary"`
	Subject              string               `json:"subject"`
	Payload              string               `json:"payload"`
	AdditionalFacts      string               `json:"additional_facts,omitempty"`
	AdditionalAttributes string               `json:"additional_attributes,omitempty"`
	Facts                map[string]FieldSpec `json:"facts,omitempty"`
	Attributes           map[string]FieldSpec `json:"attributes,omitempty"`
	Prohibited           []string             `json:"prohibited"`
}

type CatalogueRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type Catalogue struct {
	Ref        CatalogueRef         `json:"catalogue"`
	EventTypes map[string]EventType `json:"event_types"`
}

// KEEN returns the embedded KEEN catalogue.
func KEEN() *Catalogue {
	c, err := ParseCatalogue(keenCatalogue)
	if err != nil {
		panic("embedded catalogue: " + err.Error())
	}
	return c
}

// ParseCatalogue strictly decodes and checks an implementor's catalogue.
func ParseCatalogue(data []byte) (*Catalogue, error) {
	var raw struct {
		Catalogue struct {
			ID          string `json:"id"`
			Version     string `json:"version"`
			Description string `json:"description"`
		} `json:"catalogue"`
		Classifications map[string]string    `json:"classifications"`
		EventTypes      map[string]EventType `json:"event_types"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&raw); err != nil {
		return nil, err
	}
	c := &Catalogue{Ref: CatalogueRef{raw.Catalogue.ID, raw.Catalogue.Version}, EventTypes: raw.EventTypes}
	if c.Ref.ID == "" || c.Ref.Version == "" || len(c.EventTypes) == 0 {
		return nil, errors.New("catalogue needs an id, a version and event types")
	}
	for name, t := range c.EventTypes {
		if !regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,4}$`).MatchString(name) {
			return nil, fmt.Errorf("invalid event type %q", name)
		}
		if t.Class != "observation" && t.Class != "event" {
			return nil, fmt.Errorf("%s: class must be observation or event", name)
		}
		for _, pair := range []struct {
			fields map[string]FieldSpec
			policy string
		}{{t.Facts, t.AdditionalFacts}, {t.Attributes, t.AdditionalAttributes}} {
			switch pair.policy {
			case "", "reject", "scalar_string":
			default:
				return nil, fmt.Errorf("%s: unknown additional field policy", name)
			}
			for k, spec := range pair.fields {
				if !fieldName.MatchString(k) {
					return nil, fmt.Errorf("%s: invalid field %q", name, k)
				}
				switch spec.Type {
				case "boolean", "integer", "string", "timestamp", "string_list":
				default:
					return nil, fmt.Errorf("%s.%s: unknown type", name, k)
				}
				switch spec.Classification {
				case "", "evidence_metadata", "operational", "security_sensitive":
				default:
					return nil, fmt.Errorf("%s.%s: classification cannot be sent", name, k)
				}
			}
		}
		for _, v := range []string{t.Subject, t.Payload} {
			switch v {
			case "forbidden", "optional", "required":
			default:
				return nil, fmt.Errorf("%s: subject and payload must be forbidden, optional or required", name)
			}
		}
	}
	return c, nil
}

// Type returns the definition for an event type.
func (c *Catalogue) Type(name string) (EventType, error) {
	t, ok := c.EventTypes[name]
	if !ok {
		return t, fmt.Errorf("UEU_EVENT_TYPE_UNKNOWN: %s", name)
	}
	return t, nil
}

// Rejection records a field that could not be sent as its catalogue type.
type Rejection struct {
	Field  string
	Reason string
}

// Convert turns collector strings into the declared JSON types. Undeclared,
// prohibited or malformed fields are left out and reported, never guessed.
func Convert(specs map[string]FieldSpec, additional string, prohibited []string, values map[string]string) (map[string]any, []Rejection) {
	out := map[string]any{}
	var rejected []Rejection
	banned := map[string]bool{}
	for _, p := range prohibited {
		banned[p] = true
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := values[k]
		if v == "" {
			continue // absent, not rejected
		}
		if banned[k] {
			rejected = append(rejected, Rejection{k, "prohibited"})
			continue
		}
		if !fieldName.MatchString(k) {
			rejected = append(rejected, Rejection{k, "invalid_name"})
			continue
		}
		spec, declared := specs[k]
		if !declared {
			if additional != "scalar_string" {
				rejected = append(rejected, Rejection{k, "undeclared"})
				continue
			}
			spec = FieldSpec{Type: "string"}
		}
		converted, ok := convertValue(spec.Type, v)
		if !ok {
			rejected = append(rejected, Rejection{k, "invalid_" + spec.Type})
			continue
		}
		if len(out) >= MaxFields {
			rejected = append(rejected, Rejection{k, "too_many_fields"})
			continue
		}
		out[k] = converted
	}
	return out, rejected
}

func convertValue(kind, v string) (any, bool) {
	switch kind {
	case "boolean":
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	case "integer":
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err == nil && n <= MaxSafeInteger && n >= -MaxSafeInteger {
			return n, true
		}
	case "timestamp":
		if _, err := time.Parse(time.RFC3339Nano, v); err == nil && len(v) <= 64 {
			return v, true
		}
	case "string":
		if utf8.ValidString(v) && len(v) <= MaxString {
			return v, true
		}
	case "string_list":
		items := []any{}
		for _, item := range strings.Split(v, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if !utf8.ValidString(item) || len(item) > MaxListString || len(items) >= MaxListItems {
				return nil, false
			}
			items = append(items, item)
		}
		return items, true
	}
	return nil, false
}

// CheckTyped validates values that were already typed by the producer.
func CheckTyped(specs map[string]FieldSpec, additional string, prohibited []string, values map[string]any) error {
	if len(values) > MaxFields {
		return errors.New("UEU_SCHEMA_VALIDATION_FAILED: too many fields")
	}
	for k, v := range values {
		for _, p := range prohibited {
			if p == k {
				return fmt.Errorf("UEU_PROHIBITED_FIELD_DETECTED: %s", k)
			}
		}
		if !fieldName.MatchString(k) {
			return fmt.Errorf("UEU_SCHEMA_VALIDATION_FAILED: field name %q", k)
		}
		spec, ok := specs[k]
		if !ok {
			if additional != "scalar_string" {
				return fmt.Errorf("UEU_SCHEMA_VALIDATION_FAILED: undeclared field %s", k)
			}
			spec = FieldSpec{Type: "string"}
		}
		if !typedOK(spec.Type, v) {
			return fmt.Errorf("UEU_SCHEMA_VALIDATION_FAILED: %s is not %s", k, spec.Type)
		}
	}
	return nil
}

func typedOK(kind string, v any) bool {
	switch kind {
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "integer":
		switch n := v.(type) {
		case int64:
			return n <= MaxSafeInteger && n >= -MaxSafeInteger
		case int:
			return int64(n) <= MaxSafeInteger && int64(n) >= -MaxSafeInteger
		case json.Number:
			_, err := strconv.ParseInt(string(n), 10, 64)
			return err == nil
		}
	case "string":
		s, ok := v.(string)
		return ok && utf8.ValidString(s) && len(s) <= MaxString
	case "timestamp":
		s, ok := v.(string)
		if !ok || len(s) > 64 {
			return false
		}
		_, err := time.Parse(time.RFC3339Nano, s)
		return err == nil
	case "string_list":
		items, ok := v.([]any)
		if !ok || len(items) > MaxListItems {
			return false
		}
		for _, item := range items {
			s, ok := item.(string)
			if !ok || len(s) > MaxListString || !utf8.ValidString(s) {
				return false
			}
		}
		return true
	}
	return false
}
