// Package keentest is KEEN's side of the agent transport, for tests: an
// identity key, encryption keys, the server-key document, opening sealed
// requests and sealing responses. It mirrors app/agents/server_keys.py.
package keentest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"keen-agent/internal/ueu"
)

const (
	SealedType         = "application/vnd.keen.sealed"
	SealedResponseType = "application/vnd.keen.sealed-response"
)

// KEEN holds a test KEEN's keys.
type KEEN struct {
	Identity    ed25519.PrivateKey
	Fingerprint string
	Current     string
	keys        map[string]hpke.PrivateKey
	statements  map[string]map[string]any
	signatures  map[string]string
}

// New makes a KEEN with an identity and one encryption key. The key is valid
// for a year (KEEN's are valid for 37 days) so tests can move the clock to a
// credential renewal without also exercising key rotation.
func New() *KEEN {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	k := &KEEN{Identity: priv, keys: map[string]hpke.PrivateKey{}, statements: map[string]map[string]any{}, signatures: map[string]string{}}
	sum := sha256.Sum256(priv.Public().(ed25519.PublicKey))
	k.Fingerprint = base64.RawURLEncoding.EncodeToString(sum[:16])
	k.Rotate(time.Now().Add(365 * 24 * time.Hour))
	return k
}

// Rotate makes a new current encryption key, keeping the earlier ones.
func (k *KEEN) Rotate(notAfter time.Time) string {
	priv, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		panic(err)
	}
	public := priv.PublicKey().Bytes()
	sum := sha256.Sum256(public)
	kid := hex.EncodeToString(sum[:8])
	statement := map[string]any{
		"aead": "AES-256-GCM", "context": "keen-agent-encryption-key-v1", "identity": k.Fingerprint,
		"issued_at": time.Now().UTC().Format(time.RFC3339), "kdf": "HKDF-SHA256", "kem": "MLKEM768-X25519",
		"key_id": kid, "not_after": notAfter.UTC().Format(time.RFC3339), "public_key": base64.RawURLEncoding.EncodeToString(public),
	}
	canonical, err := ueu.Canonical(statement)
	if err != nil {
		panic(err)
	}
	k.keys[kid], k.statements[kid] = priv, statement
	k.signatures[kid] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.Identity, canonical))
	k.Current = kid
	return kid
}

// Forget erases an encryption key, as KEEN does once agents may not use it.
func (k *KEEN) Forget(kid string) { delete(k.keys, kid) }

// Credential returns an enrolment code (kc) or bootstrap key (ke) pinning
// this KEEN.
func (k *KEEN) Credential(kind, id string) string {
	return kind + "_" + id + "." + strings.Repeat("A", 43) + "." + k.Fingerprint
}

// Document is the server-key document for the current key.
func (k *KEEN) Document() []byte {
	doc, _ := json.Marshal(map[string]any{
		"identity":       map[string]any{"algorithm": "ed25519", "fingerprint": k.Fingerprint, "public_key": base64.RawURLEncoding.EncodeToString(k.Identity.Public().(ed25519.PublicKey))},
		"encryption_key": k.statements[k.Current],
		"signature":      k.signatures[k.Current],
	})
	return doc
}

// ServeKey answers GET /v1/agents/server-key.
func (k *KEEN) ServeKey(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(k.Document())
}

func requestInfo(operation, kid, agentKeyID string) []byte {
	return []byte("keen-agent-request-v1\x00" + operation + "\x00" + kid + "\x00" + agentKeyID)
}

// Opened is a decrypted request.
type Opened struct {
	Body        []byte
	ResponseKey []byte
	Operation   string
}

// Open decrypts a sealed request as KEEN does. A non-zero status is the
// HTTP status KEEN would refuse it with.
func (k *KEEN) Open(r *http.Request, body []byte, operation, agentKeyID string) (Opened, int) {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != SealedType {
		return Opened{}, http.StatusUnsupportedMediaType
	}
	kid := r.Header.Get("Keen-Encryption-Key")
	priv, ok := k.keys[kid]
	if !ok {
		return Opened{}, http.StatusMisdirectedRequest
	}
	plain, err := hpke.Open(priv, hpke.HKDFSHA256(), hpke.AES256GCM(), requestInfo(operation, kid, agentKeyID), body)
	if err != nil || len(plain) < 32 {
		return Opened{}, http.StatusBadRequest
	}
	return Opened{Body: plain[32:], ResponseKey: plain[:32], Operation: operation}, 0
}

// SealResponse encrypts a response with the request's response key.
func SealResponse(o Opened, status int, payload []byte) []byte {
	block, _ := aes.NewCipher(o.ResponseKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	aad := []byte(fmt.Sprintf("keen-agent-response-v1\x00%s\x00%d", o.Operation, status))
	return append(nonce, gcm.Seal(nil, nonce, payload, aad)...)
}

// Reply writes a sealed success response naming the current key.
func (k *KEEN) Reply(w http.ResponseWriter, o Opened, status int, payload []byte) {
	w.Header().Set("Content-Type", SealedResponseType)
	w.Header().Set("Keen-Encryption-Key", k.Current)
	w.WriteHeader(status)
	w.Write(SealResponse(o, status, payload))
}
