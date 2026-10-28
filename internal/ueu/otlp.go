package ueu

import (
	"encoding/json"
	"strconv"
)

// Resource attribute names of KEEN's OTLP binding. The signed manifest and
// the envelope bodies are authoritative; every other attribute is a hint.
const (
	AttrSpecVersion = "ueu.spec_version"
	AttrEvidenceID  = "ueu.evidence_id"
	AttrInstance    = "ueu.producer.instance_id"
	AttrManifest    = "ueu.batch.manifest"
	AttrSignature   = "ueu.batch.signature"
	AttrKeyID       = "ueu.batch.key_id"
)

func stringAttr(k, v string) map[string]any {
	return map[string]any{"key": k, "value": map[string]string{"stringValue": v}}
}

// Severity maps an outcome to an OTLP severity number.
func Severity(outcome string) int {
	if outcome == "failure" {
		return 13 // WARN
	}
	return 9 // INFO
}

// OTLPRequest encodes one signed batch as OTLP/HTTP JSON logs: each record's
// body is the envelope's exact canonical bytes.
func OTLPRequest(service, version, instance, keyID string, manifest []byte, signature string, batch []Sealed) ([]byte, error) {
	records := make([]any, 0, len(batch))
	for _, s := range batch {
		records = append(records, map[string]any{
			"timeUnixNano":   strconv.FormatInt(s.EventTime.UnixNano(), 10),
			"severityNumber": Severity(s.Outcome),
			"body":           map[string]string{"stringValue": string(s.Canonical)},
			"attributes": []any{
				stringAttr("event.name", s.EventType),
				stringAttr(AttrSpecVersion, SpecVersion),
				stringAttr(AttrEvidenceID, s.EvidenceID),
			},
		})
	}
	resource := []any{
		stringAttr("service.name", service),
		stringAttr("service.version", version),
		stringAttr(AttrInstance, instance),
	}
	if manifest != nil {
		resource = append(resource, stringAttr(AttrManifest, string(manifest)), stringAttr(AttrSignature, signature), stringAttr(AttrKeyID, keyID))
	}
	return json.Marshal(map[string]any{"resourceLogs": []any{map[string]any{
		"resource":  map[string]any{"attributes": resource},
		"scopeLogs": []any{map[string]any{"scope": map[string]string{"name": service, "version": version}, "logRecords": records}},
	}}})
}
