package ueu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// transportVectors pins KEEN's end-to-end transport for the Python side:
// the identity fingerprint, a signed encryption key statement, the HPKE
// request info and a sealed response.
func transportVectors(t *testing.T, agentKeyID string) map[string]any {
	t.Helper()
	identitySeed := bytes.Repeat([]byte{0x43}, ed25519.SeedSize)
	identity := ed25519.NewKeyFromSeed(identitySeed)
	sum := sha256.Sum256(identity.Public().(ed25519.PublicKey))
	fingerprint := base64.RawURLEncoding.EncodeToString(sum[:16])
	hpkeSeed := bytes.Repeat([]byte{0x44}, 32)
	priv, err := hpke.MLKEM768X25519().NewPrivateKey(hpkeSeed)
	if err != nil {
		t.Fatal(err)
	}
	public := priv.PublicKey().Bytes()
	keySum := sha256.Sum256(public)
	kid := hex.EncodeToString(keySum[:8])
	statement := map[string]any{
		"aead": "AES-256-GCM", "context": "keen-agent-encryption-key-v1", "identity": fingerprint,
		"issued_at": "2026-11-01T00:00:00Z", "kdf": "HKDF-SHA256", "kem": "MLKEM768-X25519",
		"key_id": kid, "not_after": "2026-12-08T00:00:00Z", "public_key": base64.RawURLEncoding.EncodeToString(public),
	}
	canonical, err := Canonical(statement)
	if err != nil {
		t.Fatal(err)
	}
	responseKey := bytes.Repeat([]byte{0x45}, 32)
	nonce := bytes.Repeat([]byte{0x46}, 12)
	block, _ := aes.NewCipher(responseKey)
	gcm, _ := cipher.NewGCM(block)
	payload := []byte(`{"ok":true}`)
	aad := []byte("keen-agent-response-v1\x00heartbeat\x00200")
	info := "keen-agent-request-v1\x00heartbeat\x00" + kid + "\x00" + agentKeyID
	return map[string]any{
		"server_identity_seed_hex":       hexOf(identitySeed),
		"server_identity_public_key":     base64.RawURLEncoding.EncodeToString(identity.Public().(ed25519.PublicKey)),
		"server_fingerprint":             fingerprint,
		"encryption_seed_hex":            hexOf(hpkeSeed),
		"encryption_statement":           string(canonical),
		"encryption_statement_signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(identity, canonical)),
		"sealed_request_info":            info,
		"sealed_request_plaintext":       base64.RawURLEncoding.EncodeToString(append(append([]byte{}, responseKey...), payload...)),
		"response_key_hex":               hexOf(responseKey),
		"response_aad":                   string(aad),
		"response_payload":               string(payload),
		"sealed_response":                base64.RawURLEncoding.EncodeToString(append(append([]byte{}, nonce...), gcm.Seal(nil, nonce, payload, aad)...)),
	}
}

func vectorKey(t *testing.T, v map[string]any) hpke.PrivateKey {
	seed, _ := hex.DecodeString(v["encryption_seed_hex"].(string))
	priv, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func sealVector(t *testing.T, v map[string]any) string {
	plain, _ := base64.RawURLEncoding.DecodeString(v["sealed_request_plaintext"].(string))
	wire, err := hpke.Seal(vectorKey(t, v).PublicKey(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(v["sealed_request_info"].(string)), plain)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(wire)
}

func openVector(t *testing.T, v map[string]any, wire string) {
	raw, err := base64.RawURLEncoding.DecodeString(wire)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := hpke.Open(vectorKey(t, v), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(v["sealed_request_info"].(string)), raw)
	if err != nil || base64.RawURLEncoding.EncodeToString(plain) != v["sealed_request_plaintext"] {
		t.Fatal("saved sealed request does not open", err)
	}
}
