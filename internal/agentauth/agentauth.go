// Package agentauth implements KEEN agent enrolment, key renewal and signed
// requests. One Ed25519 key pair per agent authenticates every request and
// signs the evidence; KEEN stores only public keys. Every request is
// encrypted to KEEN's pinned identity, and only responses sealed with the
// request's own response key are believed (sealed.go).
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
	// Codes and bootstrap keys end with the fingerprint of KEEN's identity key.
	CodePattern      = regexp.MustCompile(`^kc_([0-9a-f-]{36})\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{22}$`)
	BootstrapPattern = regexp.MustCompile(`^ke_([0-9a-f-]{36})\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{22}$`)
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
	// Catalogue is the event catalogue KEEN last granted.
	Catalogue ueu.CatalogueRef `json:"catalogue,omitzero"`
	// Server is KEEN's pinned identity and its current encryption key.
	Server ServerKey `json:"server"`
}

// Pin records KEEN's verified identity and encryption key.
func (i *Identity) Pin(k ServerKey) { i.Server = k }

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
		if i.Server.Identity == "" {
			return errors.New("identity predates end-to-end encryption; purge the state directory and enrol again with a new code")
		}
		if err = i.Server.Validate(); err != nil {
			return err
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

// Permanent reports whether retrying soon cannot succeed: a refusal rather
// than a temporary condition. 421 means KEEN no longer accepts the encryption
// key; fetching it again resolves that.
//
// Error responses are not sealed, so anything holding a certificate for
// KEEN's address can send one. A refusal therefore never blocks the agent:
// it waits RefusalBackoff before trying again and reports the refusal.
func (e HTTPError) Permanent() bool {
	return e.Status >= 400 && e.Status < 500 && e.Status != 408 && e.Status != 421 && e.Status != 429
}

// RefusalBackoff is how long the agent waits after a refusal (Permanent).
const RefusalBackoff = time.Hour

// NeedsKeyRefresh reports whether err asks for KEEN's key to be fetched again.
func NeedsKeyRefresh(err error) bool {
	var refresh KeyRefreshNeeded
	var rejected HTTPError
	return errors.As(err, &refresh) || (errors.As(err, &rejected) && rejected.Status == http.StatusMisdirectedRequest)
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

// Response is a bounded KEEN response body, opened when it was sealed.
type Response struct {
	Status int
	Body   []byte
	// ServerKey is the encryption key KEEN names as current. It is a hint:
	// a different value prompts a verified fetch of the server-key document.
	ServerKey string
}

// do sends a request. With a response key, a success response must be
// sealed with it; its plaintext is returned. Without one (the server-key
// document, which is verified by signature) the body is returned as is.
func do(h *http.Client, req *http.Request, userAgent string, responseKey []byte, operation string) (Response, error) {
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
	out := Response{Status: res.StatusCode, Body: b}
	if v := res.Header.Get(KeyHeader); encryptionKeyPattern.MatchString(v) {
		out.ServerKey = v
	}
	if responseKey == nil {
		return out, nil
	}
	if strings.TrimSpace(strings.Split(res.Header.Get("Content-Type"), ";")[0]) != SealedResponseType {
		return Response{Status: res.StatusCode}, UntrustedResponse{"not sealed"}
	}
	if out.Body, err = OpenResponse(responseKey, operation, res.StatusCode, b); err != nil {
		return Response{Status: res.StatusCode}, err
	}
	return out, nil
}

// Post sends a request encrypted to KEEN and signed with the identity's
// current key, and returns KEEN's opened response.
func Post(ctx context.Context, h *http.Client, url, operation string, body []byte, id Identity, userAgent string) (Response, error) {
	priv, err := id.Key()
	if err != nil || !id.Enrolled() {
		return Response{}, errors.New("agent is not enrolled")
	}
	if !id.Server.Usable(time.Now()) {
		return Response{}, KeyRefreshNeeded{"no current encryption key"}
	}
	wire, responseKey, err := Seal(id.Server, operation, id.KeyID, body)
	if err != nil {
		return Response{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return Response{}, errors.New("invalid endpoint")
	}
	req.Header.Set("Content-Type", SealedType)
	req.Header.Set(KeyHeader, id.Server.EncryptionKey)
	if err = ueu.SignRequest(req, wire, operation, id.KeyID, priv, time.Now()); err != nil {
		return Response{}, err
	}
	return do(h, req, userAgent, responseKey, operation)
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
// Each attempt proves possession of the key afresh.
//
// It first fetches KEEN's server-key document and checks it against the
// identity fingerprint the credential ends with; the request, credential
// included, is then encrypted to KEEN, and the grant must open with the
// request's response key. It returns the grant and KEEN's verified key.
func Enroll(ctx context.Context, h *http.Client, id Identity, credential, userAgent string) (Grant, ServerKey, error) {
	var g Grant
	priv, err := id.Key()
	if err != nil {
		return g, ServerKey{}, err
	}
	credential = strings.TrimSpace(credential)
	pinned, err := CredentialFingerprint(credential)
	if err != nil {
		return g, ServerKey{}, err
	}
	server, err := FetchServerKey(ctx, h, id.Endpoint, pinned, userAgent, time.Now())
	if err != nil {
		return g, ServerKey{}, err
	}
	body := map[string]any{"public_key": publicKey(priv), "credential": credential}
	switch {
	case CodePattern.MatchString(credential):
	case BootstrapPattern.MatchString(credential):
		if !namePattern.MatchString(id.Name) || !noncePattern.MatchString(id.EnrollmentNonce) {
			return g, ServerKey{}, errors.New("profile enrolment needs a valid name and saved nonce")
		}
		body["name"], body["nonce"] = id.Name, id.EnrollmentNonce
	}
	// Every attempt, retries included, signs a fresh proof: KEEN accepts each
	// proof nonce once and only near its creation time, so a recorded request
	// cannot be replayed to fetch the grant.
	proofNonce, err := NewSecret()
	if err != nil {
		return g, ServerKey{}, err
	}
	created := time.Now().Unix()
	body["created"], body["proof_nonce"] = created, proofNonce
	if body["proof"], err = proof(priv, map[string]any{"context": "keen-agent-enroll-v2", "created": created, "credential_sha256": credentialDigest(credential), "proof_nonce": proofNonce, "public_key": body["public_key"]}); err != nil {
		return g, ServerKey{}, err
	}
	encoded, _ := json.Marshal(body)
	wire, responseKey, err := Seal(server, OperationEnroll, "", encoded)
	if err != nil {
		return g, ServerKey{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, Base(id.Endpoint)+"/v1/agents/enroll", bytes.NewReader(wire))
	if err != nil {
		return g, ServerKey{}, errors.New("invalid endpoint")
	}
	req.Header.Set("Content-Type", SealedType)
	req.Header.Set(KeyHeader, server.EncryptionKey)
	req.Header.Set("Keen-Agent-Operation", OperationEnroll)
	res, err := do(h, req, userAgent, responseKey, OperationEnroll)
	if err != nil {
		return g, ServerKey{}, err
	}
	if json.Unmarshal(res.Body, &g) != nil {
		return g, ServerKey{}, errors.New("invalid enrolment response")
	}
	return g, server, nil
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
	i.SubjectType, i.Ceiling, i.Catalogue = g.Subject.Type, g.Ceiling, g.Catalogue
	i.EnrollmentNonce, i.RenewalNonce, i.RenewalKey = "", "", ""
	i.Blocked, i.Failures, i.NextAttempt = "", 0, time.Time{}
	return nil
}

var unpinnedCredential = regexp.MustCompile(`^k[ce]_[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$`)

// ReadCredential trims and checks an enrolment code or bootstrap key.
func ReadCredential(b []byte) (string, error) {
	v := strings.TrimSpace(string(b))
	if unpinnedCredential.MatchString(v) {
		return "", errors.New("this enrolment code or bootstrap key was issued by a KEEN release without end-to-end encryption; issue a new one")
	}
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
