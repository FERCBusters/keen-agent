package ueu

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var fixed = time.Date(2026, 10, 27, 6, 43, 38, 95_000_000, time.UTC)

func producer(t *testing.T) Producer {
	t.Helper()
	return Producer{
		Catalogue: KEEN(), ApplicationID: "keen-agent", ApplicationVersion: "0.2.0",
		InstanceID: "4f1c9a2e-0000-4000-8000-000000000001", AssetType: "workstation", Platform: "windows",
		Subject: Subject{Type: "pairwise", Key: bytes.Repeat([]byte{7}, 32)},
	}
}

func TestObservationEnvelope(t *testing.T) {
	p := producer(t)
	kind, value, scope := LocalAccount("S-1-5-21-2794457514-3556696545-1978787537-1001")
	env, err := p.Observe(Observation{
		Check: "screen_lock", Provider: "windows_user_policy", Scope: scope, Status: "observed",
		Reason: "user_lock_settings_observed", ObservedAt: fixed, SubjectKind: kind, SubjectValue: value,
		Facts: map[string]string{
			"automatic_lock_configured": "true", "lock_after_seconds": "1800", "lock_paths": "sleep_with_sign_in",
			"saver_enabled": "true", "screensaver_selected": "false", "idle_seconds": "soon",
			"password": "never-sent", "vendor_hint": "kept as text",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := env["observation"].(map[string]any)["facts"].(map[string]any)
	if facts["automatic_lock_configured"] != true || facts["lock_after_seconds"] != int64(1800) || facts["vendor_hint"] != "kept as text" {
		t.Fatal(facts)
	}
	if _, ok := facts["password"]; ok {
		t.Fatal("prohibited fact sent")
	}
	if _, ok := facts["idle_seconds"]; ok {
		t.Fatal("malformed integer sent")
	}
	transformations := env["privacy"].(map[string]any)["transformations"].([]any)
	joined, _ := json.Marshal(transformations)
	for _, want := range []string{"subject-pseudonymised", "removed:password:prohibited", "removed:idle_seconds:invalid_integer"} {
		if !strings.Contains(string(joined), want) {
			t.Fatalf("missing %s in %s", want, joined)
		}
	}
	b, _ := Canonical(env)
	if strings.Contains(string(b), "S-1-5-21") {
		t.Fatal("account identifier disclosed")
	}
	if env["subject"].(map[string]any)["identifier_type"] != "pairwise" {
		t.Fatal(env["subject"])
	}
	if _, err = p.Observe(Observation{Check: "screen_lock", Status: "unknown", ObservedAt: fixed}); err == nil {
		t.Fatal("unknown probe became evidence")
	}
	if _, err = p.Observe(Observation{Check: "disk_encryption", Provider: "bitlocker", Scope: "C:", Status: "observed", ObservedAt: fixed, SubjectKind: "unix_uid", SubjectValue: "0"}); err == nil {
		t.Fatal("subject accepted where forbidden")
	}
	if _, err = p.Observe(Observation{Check: "made_up", Status: "observed", Scope: "x", ObservedAt: fixed}); err == nil || !strings.Contains(err.Error(), "UEU_EVENT_TYPE_UNKNOWN") {
		t.Fatal(err)
	}
}

func TestTransformationsAreBoundedAndNameless(t *testing.T) {
	p := producer(t)
	facts := map[string]string{"Secret Name=hunter2": "x"}
	for i := 0; i < 100; i++ {
		facts[fmt.Sprintf("idle_seconds_%03d", i)] = "x"
	}
	facts["idle_seconds"] = "soon"
	env, err := p.Observe(Observation{Check: "session_inventory", Provider: "loginctl", Scope: "host", Status: "observed", Reason: "r", ObservedAt: fixed, Facts: facts})
	if err != nil {
		t.Fatal(err)
	}
	list := env["privacy"].(map[string]any)["transformations"].([]any)
	if len(list) != MaxTransformations || list[len(list)-1] != "removed:further_fields:truncated" {
		t.Fatal(len(list), list[len(list)-1])
	}
	b, _ := Canonical(env)
	if strings.Contains(string(b), "hunter2") || !strings.Contains(string(b), "removed:unnamed:invalid_name") {
		t.Fatal(string(b))
	}
}

func TestSubjectsArePairwiseOrPublic(t *testing.T) {
	a := Subject{"pairwise", bytes.Repeat([]byte{1}, 32)}
	b := Subject{"pairwise", bytes.Repeat([]byte{2}, 32)}
	x, _ := a.Pseudonym("unix_uid", "1000")
	y, _ := b.Pseudonym("unix_uid", "1000")
	z, _ := a.Pseudonym("windows_sid", "1000")
	if x == y || x == z || !strings.HasPrefix(x, "hmac-sha256:") {
		t.Fatal(x, y, z)
	}
	if _, err := (Subject{"public", []byte("short")}).Pseudonym("unix_uid", "1"); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestEventPayloadFollowsModeAndCatalogue(t *testing.T) {
	p := producer(t)
	line := "2026-01-01 00:00:00 upgrade example:amd64 1.0 1.1"
	base := Event{Type: "software.package.changed", Component: "dpkg", Action: "upgrade", Outcome: "success", Time: fixed, SourceRecord: line,
		Attributes: map[string]string{"manager": "dpkg", "action": "upgrade", "package": "example:amd64", "old_version": "1.0", "new_version": "1.1", "surprise": "x"}}
	env, err := p.Emit(base)
	if err != nil {
		t.Fatal(err)
	}
	evidence := env["evidence"].(map[string]any)
	if evidence["payload_included"] != false || evidence["payload"] != nil || !strings.HasPrefix(evidence["payload_hash"].(string), "sha256:") {
		t.Fatal(evidence)
	}
	if _, ok := env["attributes"].(map[string]any)["surprise"]; ok {
		t.Fatal("undeclared attribute sent")
	}
	base.IncludePayload, base.Mode = true, ModeEventsAndLines
	env, err = p.Emit(base)
	if err != nil || env["evidence"].(map[string]any)["payload"] != line || env["evidence"].(map[string]any)["collection_mode"] != "events_with_lines" {
		t.Fatal(env["evidence"], err)
	}
	if _, err = p.Emit(Event{Type: "log.line.collected", Component: "nginx", Action: "collect", Outcome: "info", Time: fixed}); err == nil {
		t.Fatal("payload-required event accepted without a line")
	}
	if _, err = p.Emit(Event{Type: "evidence.records.discarded", Component: "queue", Action: "discard", Outcome: "info", Time: fixed, SourceRecord: "x", IncludePayload: true}); err == nil {
		t.Fatal("payload accepted where forbidden")
	}
	if _, err = p.Emit(Event{Type: "software.package.changed", Outcome: "triumph", Time: fixed}); err == nil {
		t.Fatal("unknown outcome accepted")
	}
}

func TestModes(t *testing.T) {
	m, err := ParseMode("")
	if err != nil || m != ModeEvents || m.IncludesLines() {
		t.Fatal(m, err)
	}
	if _, err = ParseMode("everything"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if !ModeEventsAndLines.Within(ModeAllLines) || ModeAllLines.Within(ModeEvents) || !ModeAllLines.IncludesLines() {
		t.Fatal("mode ordering")
	}
}

func TestSealChainsAndManifestSigns(t *testing.T) {
	p := producer(t)
	var chain Chain
	var sealed []Sealed
	for i := 0; i < 3; i++ {
		env, err := p.Emit(Event{Type: "evidence.records.discarded", Component: "queue", Action: "discard", Outcome: "info", Time: fixed, Attributes: map[string]string{"reason": "operator_purge", "count": "2"}})
		if err != nil {
			t.Fatal(err)
		}
		s, err := Seal(env, p.InstanceID, &chain, fixed)
		if err != nil {
			t.Fatal(err)
		}
		sealed = append(sealed, s)
	}
	for i, s := range sealed {
		var env map[string]any
		json.Unmarshal(s.Canonical, &env)
		integrity := env["integrity"].(map[string]any)
		if integrity["sequence"].(float64) != float64(i+1) {
			t.Fatal(integrity)
		}
		if i == 0 && integrity["previous_evidence_hash"] != nil {
			t.Fatal("first link has a predecessor")
		}
		if i > 0 && integrity["previous_evidence_hash"] != sealed[i-1].Hash {
			t.Fatal("chain broken")
		}
		if HashEnvelope(s.Canonical) != s.Hash || !ValidEvidenceID(s.EvidenceID) {
			t.Fatal("hash or identifier")
		}
	}
	if chain.Sequence != 3 || chain.LastHash != sealed[2].Hash {
		t.Fatal(chain)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := KeyID(p.InstanceID, pub)
	manifest, err := Manifest(p.InstanceID, keyID, fixed, sealed)
	if err != nil {
		t.Fatal(err)
	}
	sig := SignManifest(priv, manifest)
	if VerifyManifest(pub, manifest, sig) != nil {
		t.Fatal("manifest does not verify")
	}
	tampered := bytes.Replace(manifest, []byte(sealed[0].Hash), []byte(sealed[1].Hash), 1)
	if VerifyManifest(pub, tampered, sig) == nil {
		t.Fatal("tampered manifest verified")
	}
	body, err := OTLPRequest("keen-agent", "0.2.0", p.InstanceID, keyID, manifest, sig, sealed)
	if err != nil || !bytes.Contains(body, []byte(AttrManifest)) {
		t.Fatal(err)
	}
}

func TestRequestSignatureBindsOperationBodyAndTime(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := KeyID("4f1c9a2e-0000-4000-8000-000000000001", pub)
	body := []byte(`{"ok":true}`)
	req, _ := http.NewRequest("POST", "https://keen.example/api/v1/agents/heartbeat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if err := SignRequest(req, body, OperationHeartbeat, keyID, priv, fixed); err != nil {
		t.Fatal(err)
	}
	lookup := func(k string) (ed25519.PublicKey, error) { return pub, nil }
	if _, err := VerifyRequest(req.Header, "POST", OperationHeartbeat, body, lookup, fixed.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for name, check := range map[string]func() error{
		"operation": func() error { _, e := VerifyRequest(req.Header, "POST", OperationLogs, body, lookup, fixed); return e },
		"body": func() error {
			_, e := VerifyRequest(req.Header, "POST", OperationHeartbeat, []byte(`{}`), lookup, fixed)
			return e
		},
		"stale": func() error {
			_, e := VerifyRequest(req.Header, "POST", OperationHeartbeat, body, lookup, fixed.Add(6*time.Minute))
			return e
		},
		"method": func() error {
			_, e := VerifyRequest(req.Header, "PUT", OperationHeartbeat, body, lookup, fixed)
			return e
		},
	} {
		if check() == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// TestVectors pins byte-exact outputs KEEN's Python implementation must
// reproduce. Regenerate with UPDATE_VECTORS=1 only for a deliberate change.
func TestVectors(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	p := producer(t)
	env, err := p.Observe(Observation{Check: "screen_lock", Provider: "windows_user_policy", Scope: "user", Status: "observed",
		Reason: "user_lock_settings_observed", ObservedAt: fixed, SubjectKind: "windows_sid", SubjectValue: "S-1-5-21-1-2-3-1001",
		Facts: map[string]string{"automatic_lock_configured": "true", "lock_after_seconds": "1800", "lock_paths": "sleep_with_sign_in", "screensaver_selected": "false"}})
	if err != nil {
		t.Fatal(err)
	}
	env["evidence_id"] = "0192c4e1-7a3e-7c41-9a8e-5b1d2f3c4a5b"
	chain := Chain{Sequence: 41, LastHash: "sha256:" + strings.Repeat("ab", 32)}
	s, err := Seal(env, p.InstanceID, &chain, fixed.Add(6*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	keyID := KeyID(p.InstanceID, pub)
	manifest, _ := Manifest(p.InstanceID, keyID, fixed, []Sealed{s})
	params := signatureParams(fixed.Unix(), keyID, "AAAAAAAAAAAAAAAAAAAAAA")
	body := []byte(`{"version":"0.2.0"}`)
	base := SignatureBase("POST", OperationHeartbeat, ContentDigest(body), "application/json", params)
	vectors := map[string]any{
		"seed_hex":           strings.ToLower(hexOf(seed)),
		"public_key":         base64.RawURLEncoding.EncodeToString(pub),
		"key_id":             keyID,
		"subject_key_hex":    hexOf(p.Subject.Key),
		"subject_kind":       "windows_sid",
		"subject_value":      "S-1-5-21-1-2-3-1001",
		"subject_identifier": env["subject"].(map[string]any)["identifier"],
		"envelope":           string(s.Canonical),
		"evidence_hash":      s.Hash,
		"manifest":           string(manifest),
		"manifest_signature": SignManifest(priv, manifest),
		"request_body":       string(body),
		"content_digest":     ContentDigest(body),
		"signature_input":    "keen=" + params,
		"signature_base":     base,
		"signature":          "keen=:" + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(base))) + ":",
	}
	got, _ := json.MarshalIndent(vectors, "", "  ")
	got = append(got, '\n')
	path := "testdata/vectors.json"
	if os.Getenv("UPDATE_VECTORS") == "1" {
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("vectors changed:\n%s", got)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func TestFutureEventTimesBecomeCollectionTime(t *testing.T) {
	p := producer(t)
	env, err := p.Emit(Event{Type: "software.package.changed", Component: "dpkg", Action: "upgrade", Outcome: "success", Reason: "r",
		Time: time.Now().Add(9 * time.Hour), Attributes: map[string]string{"manager": "dpkg"}})
	if err != nil {
		t.Fatal(err)
	}
	when, _ := time.Parse(TimeFormat, env["event_time"].(string))
	if when.After(time.Now().Add(time.Second)) {
		t.Fatal(env["event_time"])
	}
}
