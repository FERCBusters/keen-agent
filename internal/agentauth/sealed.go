package agentauth

// End-to-end encryption to KEEN.
//
// TLS protects a request only as far as whatever holds a certificate for
// KEEN's hostname: a reverse proxy, a load balancer, an inspecting middlebox,
// or an impostor that obtained one. So the agent encrypts every request to
// KEEN itself, and believes a response only when it decrypts with a key the
// agent sent inside that request.
//
// Every enrolment code and bootstrap key ends with the fingerprint of KEEN's
// identity key (Ed25519). The agent pins it, and fetches KEEN's server-key
// document: the identity public key and an encryption key (HPKE,
// MLKEM768-X25519 with HKDF-SHA256 and AES-256-GCM) signed by it. A request
// body is HPKE-sealed to that key; the plaintext begins with a fresh 32-byte
// response key, and KEEN seals its success response with AES-256-GCM under
// it. Only a holder of KEEN's encryption key could read the response key, so
// a response that opens is KEEN's answer to that one request.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"keen-agent/internal/ueu"
)

const (
	SealedType         = "application/vnd.keen.sealed"
	SealedResponseType = "application/vnd.keen.sealed-response"
	KeyHeader          = "Keen-Encryption-Key"

	requestContext   = "keen-agent-request-v1"
	responseContext  = "keen-agent-response-v1"
	statementContext = "keen-agent-encryption-key-v1"
	responseKeySize  = 32
	encryptionPublic = 1216

	// OperationEnroll names enrolment requests; they carry no signature.
	OperationEnroll = "enroll"
)

var (
	fingerprintPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	encryptionKeyPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// ServerKey is what the agent knows of KEEN: the pinned identity and the
// encryption key it verified with it.
type ServerKey struct {
	Identity      string    `json:"identity"`
	IdentityKey   string    `json:"identity_key"`
	EncryptionKey string    `json:"encryption_key_id"`
	PublicKey     string    `json:"encryption_public_key"`
	NotAfter      time.Time `json:"not_after"`
}

// Fingerprint names an Ed25519 identity key: 128 bits of SHA-256, base64url.
func Fingerprint(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// CredentialFingerprint returns the identity fingerprint an enrolment code
// or bootstrap key pins.
func CredentialFingerprint(credential string) (string, error) {
	credential = strings.TrimSpace(credential)
	if !CodePattern.MatchString(credential) && !BootstrapPattern.MatchString(credential) {
		return "", errors.New("not an enrolment code or bootstrap key")
	}
	return credential[strings.LastIndexByte(credential, '.')+1:], nil
}

// Validate checks a saved server key's shape and its pin.
func (k ServerKey) Validate() error {
	raw, err := base64.RawURLEncoding.DecodeString(k.IdentityKey)
	if err != nil || len(raw) != ed25519.PublicKeySize || !fingerprintPattern.MatchString(k.Identity) || Fingerprint(raw) != k.Identity {
		return errors.New("saved KEEN identity key does not match its fingerprint")
	}
	if k.EncryptionKey == "" {
		return nil
	}
	if _, err = k.public(); err != nil || !encryptionKeyPattern.MatchString(k.EncryptionKey) || k.NotAfter.IsZero() {
		return errors.New("saved KEEN encryption key is invalid")
	}
	return nil
}

func (k ServerKey) public() (hpke.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(k.PublicKey)
	if err != nil || len(raw) != encryptionPublic {
		return nil, errors.New("invalid encryption key")
	}
	return hpke.MLKEM768X25519().NewPublicKey(raw)
}

// Usable reports whether requests may be encrypted to the key now.
func (k ServerKey) Usable(now time.Time) bool {
	return k.EncryptionKey != "" && now.Before(k.NotAfter)
}

// KeyRefreshNeeded means KEEN's encryption key must be fetched again:
// KEEN no longer accepts it (HTTP 421), or it has expired.
type KeyRefreshNeeded struct{ Reason string }

func (e KeyRefreshNeeded) Error() string { return "KEEN encryption key refresh needed: " + e.Reason }

// UntrustedResponse is a success response that did not open with the
// request's response key. Nothing in it is acted on; records stay queued.
type UntrustedResponse struct{ Reason string }

func (e UntrustedResponse) Error() string {
	return "KEEN's response could not be verified (" + e.Reason + "); nothing was changed"
}

type serverKeyDocument struct {
	Identity struct {
		Algorithm   string `json:"algorithm"`
		Fingerprint string `json:"fingerprint"`
		PublicKey   string `json:"public_key"`
	} `json:"identity"`
	EncryptionKey map[string]any `json:"encryption_key"`
	Signature     string         `json:"signature"`
}

var statementFields = []string{"aead", "context", "identity", "issued_at", "kdf", "kem", "key_id", "not_after", "public_key"}

// VerifyServerKey checks a server-key document against the pinned identity
// fingerprint and returns the encryption key it vouches for.
func VerifyServerKey(body []byte, pinned string, now time.Time) (ServerKey, error) {
	var doc serverKeyDocument
	var k ServerKey
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&doc) != nil {
		return k, errors.New("invalid server-key document")
	}
	raw, err := base64.RawURLEncoding.DecodeString(doc.Identity.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize || doc.Identity.Algorithm != "ed25519" {
		return k, errors.New("invalid KEEN identity key")
	}
	if !fingerprintPattern.MatchString(pinned) || Fingerprint(raw) != pinned || doc.Identity.Fingerprint != pinned {
		return k, errors.New("KEEN's identity key does not match the fingerprint in the enrolment credential; this is not the KEEN that issued it, or KEEN's identity was replaced and the agent must enrol again")
	}
	s := doc.EncryptionKey
	if len(s) != len(statementFields) {
		return k, errors.New("invalid encryption key statement")
	}
	text := map[string]string{}
	for _, field := range statementFields {
		v, ok := s[field].(string)
		if !ok {
			return k, errors.New("invalid encryption key statement")
		}
		text[field] = v
	}
	canonical, err := ueu.Canonical(s)
	if err != nil {
		return k, errors.New("invalid encryption key statement")
	}
	sig, err := base64.RawURLEncoding.DecodeString(doc.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(raw, canonical, sig) {
		return k, errors.New("KEEN's encryption key is not signed by its identity key")
	}
	if text["context"] != statementContext || text["identity"] != pinned || text["kem"] != "MLKEM768-X25519" || text["kdf"] != "HKDF-SHA256" || text["aead"] != "AES-256-GCM" {
		return k, errors.New("unsupported encryption key statement")
	}
	public, err := base64.RawURLEncoding.DecodeString(text["public_key"])
	sum := sha256.Sum256(public)
	if err != nil || len(public) != encryptionPublic || text["key_id"] != hex.EncodeToString(sum[:8]) {
		return k, errors.New("invalid encryption key")
	}
	notAfter, err := time.Parse(time.RFC3339, text["not_after"])
	if err != nil {
		return k, errors.New("invalid encryption key expiry")
	}
	if !now.Before(notAfter) {
		return k, errors.New("KEEN's encryption key has expired; check this machine's clock")
	}
	k = ServerKey{Identity: pinned, IdentityKey: doc.Identity.PublicKey, EncryptionKey: text["key_id"], PublicKey: text["public_key"], NotAfter: notAfter}
	if _, err = k.public(); err != nil {
		return ServerKey{}, errors.New("invalid encryption key")
	}
	return k, nil
}

// FetchServerKey reads KEEN's server-key document and verifies it.
func FetchServerKey(ctx context.Context, h *http.Client, endpoint, pinned, userAgent string, now time.Time) (ServerKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, Base(endpoint)+"/v1/agents/server-key", nil)
	if err != nil {
		return ServerKey{}, errors.New("invalid endpoint")
	}
	res, err := do(h, req, userAgent, nil, "")
	if err != nil {
		return ServerKey{}, err
	}
	return VerifyServerKey(res.Body, pinned, now)
}

func requestInfo(operation, encryptionKey, agentKeyID string) []byte {
	return []byte(requestContext + "\x00" + operation + "\x00" + encryptionKey + "\x00" + agentKeyID)
}

func responseAAD(operation string, status int) []byte {
	return []byte(fmt.Sprintf("%s\x00%s\x00%d", responseContext, operation, status))
}

// Seal encrypts body to KEEN for one operation by one sender (the agent's
// key ID, or "" when enrolling). It returns the wire bytes and the key
// KEEN's response will be sealed with.
func Seal(k ServerKey, operation, agentKeyID string, body []byte) ([]byte, []byte, error) {
	pk, err := k.public()
	if err != nil {
		return nil, nil, err
	}
	responseKey := make([]byte, responseKeySize)
	if _, err = rand.Read(responseKey); err != nil {
		return nil, nil, errors.New("cannot generate response key")
	}
	plain := append(append(make([]byte, 0, len(responseKey)+len(body)), responseKey...), body...)
	wire, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), requestInfo(operation, k.EncryptionKey, agentKeyID), plain)
	if err != nil {
		return nil, nil, errors.New("cannot encrypt request")
	}
	return wire, responseKey, nil
}

// OpenResponse decrypts a sealed success response.
func OpenResponse(responseKey []byte, operation string, status int, body []byte) ([]byte, error) {
	block, err := aes.NewCipher(responseKey)
	if err != nil {
		return nil, UntrustedResponse{"invalid response key"}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(body) < gcm.NonceSize()+gcm.Overhead() {
		return nil, UntrustedResponse{"not sealed"}
	}
	plain, err := gcm.Open(nil, body[:gcm.NonceSize()], body[gcm.NonceSize():], responseAAD(operation, status))
	if err != nil {
		return nil, UntrustedResponse{"does not decrypt with this request's key"}
	}
	return plain, nil
}
