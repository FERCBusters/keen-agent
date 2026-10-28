// Package agentauth implements KEEN agent enrolment, key renewal and signed
// requests. One Ed25519 key pair per agent authenticates every request and
// signs the evidence; KEEN stores only public keys.
package agentauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"keen-agent/internal/ueu"
)

var (
	CodePattern      = regexp.MustCompile(`^kc_([0-9a-f-]{36})\.[A-Za-z0-9_-]{43}$`)
	BootstrapPattern = regexp.MustCompile(`^ke_([0-9a-f-]{36})\.[A-Za-z0-9_-]{43}$`)
	noncePattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	agentIDPattern   = regexp.MustCompile(`^[0-9a-f-]{36}$`)
	namePattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)
)

// Identity is an agent's private state. Persist it only in a protected file;
// never log it or include it in health reports.
type Identity struct {
	Endpoint        string    `json:"endpoint"`
	Name            string    `json:"name,omitempty"`
	ProfileID       string    `json:"profile_id,omitempty"`
	AgentID         string    `json:"agent_id,omitempty"`
	AssetType       string    `json:"asset_type,omitempty"`
	PrivateKey      string    `json:"private_key"`
	KeyID           string    `json:"key_id,omitempty"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
	RenewAt         time.Time `json:"renew_at,omitempty"`
	SubjectType     string    `json:"subject_type,omitempty"`
	SubjectKey      string    `json:"subject_key,omitempty"`
	PairwiseKey     string    `json:"pairwise_key"`
	Ceiling         string    `json:"evidence_mode_ceiling,omitempty"`
	EnrollmentNonce string    `json:"enrollment_nonce,omitempty"`
	RenewalNonce    string    `json:"renewal_nonce,omitempty"`
	RenewalKey      string    `json:"renewal_key,omitempty"`
	Blocked         string    `json:"blocked,omitempty"`
	Failures        int       `json:"failures,omitempty"`
	NextAttempt     time.Time `json:"next_attempt,omitempty"`
}

// Enrolled reports whether KEEN has bound this identity's key.
func (i Identity) Enrolled() bool { return i.AgentID != "" && i.KeyID != "" }

func seed(v string) (ed25519.PrivateKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("invalid private key")
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// NewSecret returns 32 random bytes as unpadded base64url.
func NewSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("cannot generate key material")
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// New starts an identity with a fresh key pair and pairwise subject key.
func New(endpoint string) (Identity, error) {
	key, err := NewSecret()
	if err != nil {
		return Identity{}, err
	}
	pairwise, err := NewSecret()
	if err != nil {
		return Identity{}, err
	}
	return Identity{Endpoint: endpoint, PrivateKey: key, PairwiseKey: pairwise}, nil
}

// Key returns the identity's signing key.
func (i Identity) Key() (ed25519.PrivateKey, error) { return seed(i.PrivateKey) }

// Validate checks a loaded identity's internal consistency.
func (i Identity) Validate() error {
	priv, err := i.Key()
	if err != nil {
		return err
	}
	if _, err = seed(i.PairwiseKey); err != nil {
		return errors.New("invalid pairwise subject key")
	}
	if i.Enrolled() {
		if !agentIDPattern.MatchString(i.AgentID) || i.KeyID != ueu.KeyID(i.AgentID, priv.Public().(ed25519.PublicKey)) || i.ExpiresAt.IsZero() {
			return errors.New("invalid enrolled identity")
		}
		if _, err = ueu.ParseMode(i.Ceiling); err != nil {
			return err
		}
		if i.SubjectType != "pairwise" && i.SubjectType != "public" {
			return errors.New("invalid subject type")
		}
	}
	if i.RenewalNonce != "" {
		if !noncePattern.MatchString(i.RenewalNonce) {
			return errors.New("invalid pending renewal")
		}
		if _, err = seed(i.RenewalKey); err != nil {
			return errors.New("invalid pending renewal key")
		}
	}
	if i.EnrollmentNonce != "" && !noncePattern.MatchString(i.EnrollmentNonce) {
		return errors.New("invalid pending enrolment")
	}
	return nil
}

// Subject returns the configured pseudonymisation key.
func (i Identity) Subject() (ueu.Subject, error) {
	raw := i.PairwiseKey
	if i.SubjectType == "public" {
		raw = i.SubjectKey
	}
	key, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(key) < 32 {
		return ueu.Subject{}, errors.New("subject key unavailable")
	}
	return ueu.Subject{Type: i.SubjectType, Key: key}, nil
}

// Ceiling returns the highest evidence mode KEEN accepts from this agent.
func (i Identity) EvidenceCeiling() ueu.Mode {
	m, err := ueu.ParseMode(i.Ceiling)
	if err != nil {
		return ueu.ModeEvents
	}
	return m
}

// HTTPError is a rejected request; 4xx other than 408 and 429 is permanent.
type HTTPError struct {
	Status int
	Retry  time.Duration
}

func (e HTTPError) Error() string { return fmt.Sprintf("KEEN returned HTTP %d", e.Status) }

// Permanent reports whether retrying cannot succeed without intervention.
func (e HTTPError) Permanent() bool {
	return e.Status >= 400 && e.Status < 500 && e.Status != 408 && e.Status != 429
}

// RetryAfter parses a Retry-After header, capped at one hour.
func RetryAfter(value string) time.Duration {
	if seconds, err := time.ParseDuration(value + "s"); err == nil {
		return max(0, min(seconds, time.Hour))
	}
	if date, err := http.ParseTime(value); err == nil {
		return max(0, min(time.Until(date), time.Hour))
	}
	return 0
}

// Base returns KEEN's API root for an OTLP logs endpoint.
func Base(endpoint string) string { return strings.TrimSuffix(endpoint, "/v1/otlp/logs") }

// Client returns an HTTPS client that verifies certificates and refuses
// redirects and proxies.
func Client(transport *http.Transport) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects refused") }}
}

// Response is a bounded KEEN response body.
type Response struct {
	Status int
	Body   []byte
}

func do(h *http.Client, req *http.Request, userAgent string) (Response, error) {
	req.Header.Set("User-Agent", userAgent)
	res, err := h.Do(req)
	if err != nil {
		return Response{}, errors.New("request failed (network/TLS)")
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(b) > 65536 {
		return Response{}, errors.New("invalid response")
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return Response{Status: res.StatusCode}, HTTPError{res.StatusCode, RetryAfter(res.Header.Get("Retry-After"))}
	}
	return Response{res.StatusCode, b}, nil
}

// Post sends a request signed with the identity's current key.
func Post(ctx context.Context, h *http.Client, url, operation string, body []byte, id Identity, userAgent string) (Response, error) {
	priv, err := id.Key()
	if err != nil || !id.Enrolled() {
		return Response{}, errors.New("agent is not enrolled")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Response{}, errors.New("invalid endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	if err = ueu.SignRequest(req, body, operation, id.KeyID, priv, time.Now()); err != nil {
		return Response{}, err
	}
	return do(h, req, userAgent)
}

// Grant is KEEN's answer to an enrolment or renewal.
type Grant struct {
	Agent struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		AgentType string `json:"agent_type"`
		ProfileID string `json:"enrollment_profile_id"`
		ExpiresAt string `json:"expires_at"`
		Enabled   bool   `json:"enabled"`
	} `json:"agent"`
	KeyID   string `json:"key_id"`
	Subject struct {
		Type string `json:"type"`
		Key  string `json:"key,omitempty"`
	} `json:"subject"`
	Ceiling   string           `json:"evidence_mode_ceiling"`
	Catalogue ueu.CatalogueRef `json:"catalogue"`
}

func credentialDigest(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(sum[:])
}

func proof(priv ed25519.PrivateKey, message map[string]any) (string, error) {
	b, err := ueu.Canonical(message)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, b)), nil
}

func publicKey(priv ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// Enroll exchanges a single-use enrolment code (kc_) or an enrolment
// profile's bootstrap key (ke_) for a binding of this identity's public key.
// Profile enrolment needs a name and the identity's saved enrolment nonce,
// so a retried request after a lost response returns the same agent.
func Enroll(ctx context.Context, h *http.Client, id Identity, credential, userAgent string) (Grant, error) {
	var g Grant
	priv, err := id.Key()
	if err != nil {
		return g, err
	}
	credential = strings.TrimSpace(credential)
	body := map[string]any{"public_key": publicKey(priv)}
	switch {
	case CodePattern.MatchString(credential):
	case BootstrapPattern.MatchString(credential):
		if !namePattern.MatchString(id.Name) || !noncePattern.MatchString(id.EnrollmentNonce) {
			return g, errors.New("profile enrolment needs a valid name and saved nonce")
		}
		body["name"], body["nonce"] = id.Name, id.EnrollmentNonce
	default:
		return g, errors.New("not an enrolment code or bootstrap key")
	}
	if body["proof"], err = proof(priv, map[string]any{"context": "keen-agent-enroll-v1", "credential_sha256": credentialDigest(credential), "public_key": body["public_key"]}); err != nil {
		return g, err
	}
	encoded, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, Base(id.Endpoint)+"/v1/agents/enroll", bytes.NewReader(encoded))
	if err != nil {
		return g, errors.New("invalid endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	res, err := do(h, req, userAgent)
	if err != nil {
		return g, err
	}
	if json.Unmarshal(res.Body, &g) != nil {
		return g, errors.New("invalid enrolment response")
	}
	return g, nil
}

// Renew asks KEEN to replace the current key with the pending renewal key.
// The request is signed by the current key; the body proves the new one.
func Renew(ctx context.Context, h *http.Client, id Identity, userAgent string) (Grant, error) {
	var g Grant
	next, err := seed(id.RenewalKey)
	if err != nil || !noncePattern.MatchString(id.RenewalNonce) {
		return g, errors.New("no pending renewal")
	}
	body := map[string]any{"public_key": publicKey(next), "nonce": id.RenewalNonce}
	if body["proof"], err = proof(next, map[string]any{"context": "keen-agent-renew-v1", "agent_id": id.AgentID, "previous_key_id": id.KeyID, "public_key": body["public_key"]}); err != nil {
		return g, err
	}
	encoded, _ := json.Marshal(body)
	res, err := Post(ctx, h, Base(id.Endpoint)+"/v1/agents/renew", ueu.OperationRenew, encoded, id, userAgent)
	if err != nil {
		return g, err
	}
	if json.Unmarshal(res.Body, &g) != nil {
		return g, errors.New("invalid renewal response")
	}
	return g, nil
}

// ParseTime reads KEEN timestamps, which may be naive UTC.
func ParseTime(value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02T15:04:05.999999999", value)
}

// Accept applies a grant for the given private key to the identity. It
// checks that KEEN bound exactly the key the agent holds.
func (i *Identity) Accept(g Grant, privateKey string, now time.Time) error {
	priv, err := seed(privateKey)
	if err != nil {
		return err
	}
	expiry, err := ParseTime(g.Agent.ExpiresAt)
	if err != nil || !expiry.After(now) || !agentIDPattern.MatchString(g.Agent.ID) || !g.Agent.Enabled {
		return errors.New("enrolment response is not usable")
	}
	if g.KeyID != ueu.KeyID(g.Agent.ID, priv.Public().(ed25519.PublicKey)) {
		return errors.New("KEEN bound a different key")
	}
	if i.AgentID != "" && g.Agent.ID != i.AgentID {
		return errors.New("enrolment response names a different agent")
	}
	if i.Name != "" && g.Agent.Name != i.Name {
		return errors.New("enrolment response names a different agent")
	}
	if _, err = ueu.ParseMode(g.Ceiling); err != nil {
		return err
	}
	switch g.Subject.Type {
	case "pairwise":
		i.SubjectKey = ""
	case "public":
		key, err := base64.RawURLEncoding.DecodeString(g.Subject.Key)
		if err != nil || len(key) < 32 {
			return errors.New("public subject key missing")
		}
		i.SubjectKey = g.Subject.Key
	default:
		return errors.New("unknown subject type")
	}
	i.AgentID, i.Name, i.ProfileID, i.AssetType = g.Agent.ID, g.Agent.Name, g.Agent.ProfileID, g.Agent.AgentType
	i.PrivateKey, i.KeyID, i.ExpiresAt = privateKey, g.KeyID, expiry
	i.RenewAt = expiry.Add(-min(7*24*time.Hour, expiry.Sub(now)/5))
	i.SubjectType, i.Ceiling = g.Subject.Type, g.Ceiling
	i.EnrollmentNonce, i.RenewalNonce, i.RenewalKey = "", "", ""
	i.Blocked, i.Failures, i.NextAttempt = "", 0, time.Time{}
	return nil
}

// ReadCredential trims and checks an enrolment code or bootstrap key.
func ReadCredential(b []byte) (string, error) {
	v := strings.TrimSpace(string(b))
	if !CodePattern.MatchString(v) && !BootstrapPattern.MatchString(v) {
		return "", errors.New("invalid enrolment code or bootstrap key")
	}
	return v, nil
}

// SignedBatch encodes sealed records as one OTLP request whose manifest is
// signed with the identity's current key.
func SignedBatch(id Identity, service, version string, batch []ueu.Sealed) ([]byte, error) {
	priv, err := id.Key()
	if err != nil || !id.Enrolled() {
		return nil, errors.New("agent is not enrolled")
	}
	manifest, err := ueu.Manifest(id.AgentID, id.KeyID, time.Now(), batch)
	if err != nil {
		return nil, err
	}
	return ueu.OTLPRequest(service, version, id.AgentID, id.KeyID, manifest, ueu.SignManifest(priv, manifest), batch)
}
