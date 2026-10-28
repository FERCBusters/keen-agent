package ueu

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// BatchContext separates batch signatures from every other signed message.
const BatchContext = "keen-ueu-batch-v1"

var evidenceIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// NewEvidenceID returns a UUIDv7 (RFC 9562) whose prefix orders it by time.
func NewEvidenceID(t time.Time) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[6:]); err != nil {
		return "", errors.New("cannot generate evidence identifier")
	}
	ms := uint64(t.UnixMilli())
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], ms)
	copy(b[:6], ts[2:])
	b[6] = 0x70 | (b[6] & 0x0f)
	b[8] = 0x80 | (b[8] & 0x3f)
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// ValidEvidenceID reports whether v is a UUIDv7 in canonical form.
func ValidEvidenceID(v string) bool { return evidenceIDPattern.MatchString(v) }

// Chain is one producer stream's position: the last sequence and its hash.
type Chain struct {
	Sequence int64  `json:"sequence"`
	LastHash string `json:"last_hash,omitempty"`
}

// Sealed is a finished envelope: its exact canonical bytes and their hash.
type Sealed struct {
	EvidenceID string
	EventType  string
	EventTime  time.Time
	Outcome    string
	Canonical  []byte
	Hash       string
	Sequence   int64
}

// Seal adds the evidence time and integrity block, canonicalises the
// envelope and advances the chain. The caller persists the new chain
// position in the same transaction that queues the envelope.
func Seal(env map[string]any, stream string, chain *Chain, now time.Time) (Sealed, error) {
	var previous any
	if chain.LastHash != "" {
		previous = chain.LastHash
	}
	next := chain.Sequence + 1
	env["evidence_time"] = now.UTC().Format(TimeFormat)
	env["integrity"] = map[string]any{
		"canonicalisation":       "RFC8785",
		"hash_algorithm":         "SHA-256",
		"stream":                 stream,
		"sequence":               next,
		"previous_evidence_hash": previous,
	}
	canonical, err := Canonical(env)
	if err != nil {
		return Sealed{}, err
	}
	if len(canonical) > 65536 {
		return Sealed{}, errors.New("UEU_SCHEMA_VALIDATION_FAILED: envelope exceeds 64 KiB")
	}
	t, err := time.Parse(TimeFormat, env["event_time"].(string))
	if err != nil {
		return Sealed{}, err
	}
	s := Sealed{
		EvidenceID: env["evidence_id"].(string),
		EventType:  env["event_type"].(string),
		EventTime:  t,
		Outcome:    env["event"].(map[string]any)["outcome"].(string),
		Canonical:  canonical,
		Hash:       HashEnvelope(canonical),
		Sequence:   next,
	}
	chain.Sequence, chain.LastHash = next, s.Hash
	return s, nil
}

// HashEnvelope returns sha256:<hex> of canonical envelope bytes.
func HashEnvelope(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// KeyID names an agent's public key: <agent id>:<first 16 hex of SHA-256>.
func KeyID(agentID string, pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return agentID + ":" + hex.EncodeToString(sum[:8])
}

// Manifest returns the canonical batch manifest a batch signature covers.
func Manifest(producer, keyID string, issuedAt time.Time, batch []Sealed) ([]byte, error) {
	entries := make([]any, 0, len(batch))
	for _, s := range batch {
		entries = append(entries, map[string]any{"evidence_id": s.EvidenceID, "evidence_hash": s.Hash})
	}
	return Canonical(map[string]any{
		"context":   BatchContext,
		"producer":  producer,
		"key_id":    keyID,
		"issued_at": issuedAt.UTC().Format(TimeFormat),
		"evidence":  entries,
	})
}

// SignManifest signs manifest bytes and returns unpadded base64url.
func SignManifest(priv ed25519.PrivateKey, manifest []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, manifest))
}

// VerifyManifest checks a batch signature.
func VerifyManifest(pub ed25519.PublicKey, manifest []byte, signature string) error {
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, manifest, sig) {
		return fmt.Errorf("UEU_EVIDENCE_VERIFICATION_FAILED")
	}
	return nil
}
