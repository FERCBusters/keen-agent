package ueu

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Agent request operations. KEEN checks the signed operation against the
// route, so a signature for one endpoint cannot be replayed at another.
const (
	OperationLogs      = "otlp-logs"
	OperationHeartbeat = "heartbeat"
	OperationRenew     = "renew"
)

const signatureComponents = `("@method" "keen-agent-operation" "content-digest" "content-type")`

// ContentDigest returns the RFC 9530 Content-Digest value for a body.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

func signatureParams(created int64, keyID, nonce string) string {
	return signatureComponents + ";created=" + strconv.FormatInt(created, 10) + `;keyid="` + keyID + `";nonce="` + nonce + `";alg="ed25519"`
}

// SignatureBase builds the RFC 9421 signature base for KEEN's covered components.
func SignatureBase(method, operation, digest, contentType, params string) string {
	return `"@method": ` + strings.ToUpper(method) + "\n" +
		`"keen-agent-operation": ` + operation + "\n" +
		`"content-digest": ` + digest + "\n" +
		`"content-type": ` + contentType + "\n" +
		`"@signature-params": ` + params
}

var keyIDPattern = regexp.MustCompile(`^[0-9a-f-]{36}:[0-9a-f]{16}$`)

// SignRequest adds Content-Digest, the operation and an RFC 9421 signature.
func SignRequest(req *http.Request, body []byte, operation, keyID string, priv ed25519.PrivateKey, now time.Time) error {
	if !keyIDPattern.MatchString(keyID) {
		return errors.New("invalid key identifier")
	}
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		return errors.New("cannot generate request nonce")
	}
	nonce := base64.RawURLEncoding.EncodeToString(n[:])
	digest := ContentDigest(body)
	contentType := req.Header.Get("Content-Type")
	if contentType == "" {
		return errors.New("content type required before signing")
	}
	params := signatureParams(now.Unix(), keyID, nonce)
	base := SignatureBase(req.Method, operation, digest, contentType, params)
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Keen-Agent-Operation", operation)
	req.Header.Set("Signature-Input", "keen="+params)
	req.Header.Set("Signature", "keen=:"+base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(base)))+":")
	return nil
}

var signatureInput = regexp.MustCompile(`^keen=\("@method" "keen-agent-operation" "content-digest" "content-type"\);created=([0-9]{1,12});keyid="([0-9a-f-]{36}:[0-9a-f]{16})";nonce="([A-Za-z0-9_-]{22})";alg="ed25519"$`)
var signatureValue = regexp.MustCompile(`^keen=:([A-Za-z0-9+/]{86}==):$`)

// SignedRequest is what a verifier learns from KEEN's signature headers.
type SignedRequest struct {
	KeyID, Nonce string
	Created      time.Time
}

// VerifyRequest checks headers against a public key. It is the reference for
// KEEN's own verifier and used by the agent's tests.
func VerifyRequest(h http.Header, method, operation string, body []byte, lookup func(keyID string) (ed25519.PublicKey, error), now time.Time) (SignedRequest, error) {
	var r SignedRequest
	m := signatureInput.FindStringSubmatch(h.Get("Signature-Input"))
	s := signatureValue.FindStringSubmatch(h.Get("Signature"))
	if m == nil || s == nil || h.Get("Keen-Agent-Operation") != operation {
		return r, errors.New("missing or malformed signature")
	}
	created, _ := strconv.ParseInt(m[1], 10, 64)
	r = SignedRequest{KeyID: m[2], Nonce: m[3], Created: time.Unix(created, 0)}
	if d := now.Sub(r.Created); d > 5*time.Minute || d < -5*time.Minute {
		return r, errors.New("signature outside the time window")
	}
	digest := ContentDigest(body)
	if h.Get("Content-Digest") != digest {
		return r, errors.New("content digest mismatch")
	}
	pub, err := lookup(r.KeyID)
	if err != nil {
		return r, err
	}
	sig, _ := base64.StdEncoding.DecodeString(s[1])
	base := SignatureBase(method, operation, digest, h.Get("Content-Type"), strings.TrimPrefix(h.Get("Signature-Input"), "keen="))
	if !ed25519.Verify(pub, []byte(base), sig) {
		return r, fmt.Errorf("signature invalid")
	}
	return r, nil
}
