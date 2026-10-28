package agentauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"keen-agent/internal/ueu"
)

type memoryStore struct {
	id    *Identity
	saves int
	fail  bool
}

func (m *memoryStore) Load() (Identity, error) {
	if m.id == nil {
		return Identity{}, os.ErrNotExist
	}
	return *m.id, nil
}
func (m *memoryStore) Save(id Identity) error {
	if m.fail {
		return errors.New("disk full")
	}
	m.saves++
	m.id = &id
	return nil
}

const agentID = "6f8459a2-2768-41a4-94d5-a0cdcc2d7187"

// fakeKEEN verifies proofs and request signatures like KEEN does.
type fakeKEEN struct {
	t        *testing.T
	keys     map[string]ed25519.PublicKey
	nonces   map[string]string
	proofs   map[string]bool
	status   int
	enrolled int
	renewed  int
}

func (f *fakeKEEN) grant(w http.ResponseWriter, pub string, profile string) {
	raw, _ := base64.RawURLEncoding.DecodeString(pub)
	key := ed25519.PublicKey(raw)
	kid := ueu.KeyID(agentID, key)
	f.keys[kid] = key
	json.NewEncoder(w).Encode(map[string]any{
		"agent":                 map[string]any{"id": agentID, "name": "host-1", "agent_type": "server", "enrollment_profile_id": profile, "expires_at": time.Now().Add(90 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05.999999"), "enabled": true},
		"key_id":                kid,
		"subject":               map[string]any{"type": "pairwise"},
		"evidence_mode_ceiling": "events_with_lines",
		"catalogue":             map[string]any{"id": "keen", "version": "2026.10"},
	})
}

func (f *fakeKEEN) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	var req map[string]string
	json.Unmarshal(body, &req)
	pubRaw, _ := base64.RawURLEncoding.DecodeString(req["public_key"])
	proof, _ := base64.RawURLEncoding.DecodeString(req["proof"])
	switch r.URL.Path {
	case "/api/v1/agents/enroll":
		credential := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(credential))
		var stamp struct {
			Created int64 `json:"created"`
		}
		json.Unmarshal(body, &stamp)
		if d := time.Now().Unix() - stamp.Created; d > 300 || d < -300 || f.proofs[req["proof_nonce"]] {
			w.WriteHeader(400)
			return
		}
		msg, _ := ueu.Canonical(map[string]any{"context": "keen-agent-enroll-v2", "created": stamp.Created, "credential_sha256": hex.EncodeToString(sum[:]), "proof_nonce": req["proof_nonce"], "public_key": req["public_key"]})
		if !ed25519.Verify(pubRaw, msg, proof) {
			w.WriteHeader(400)
			return
		}
		f.proofs[req["proof_nonce"]] = true
		if BootstrapPattern.MatchString(credential) {
			if req["name"] != "host-1" || req["nonce"] == "" {
				w.WriteHeader(400)
				return
			}
			if old, ok := f.nonces[req["nonce"]]; ok && old != req["public_key"] {
				w.WriteHeader(409)
				return
			}
			f.nonces[req["nonce"]] = req["public_key"]
		}
		f.enrolled++
		f.grant(w, req["public_key"], "")
	case "/api/v1/agents/renew":
		signed, err := ueu.VerifyRequest(r.Header, "POST", ueu.OperationRenew, body, func(k string) (ed25519.PublicKey, error) {
			if key, ok := f.keys[k]; ok {
				return key, nil
			}
			return nil, errors.New("unknown key")
		}, time.Now())
		if err != nil {
			w.WriteHeader(401)
			return
		}
		msg, _ := ueu.Canonical(map[string]any{"context": "keen-agent-renew-v1", "agent_id": agentID, "previous_key_id": signed.KeyID, "public_key": req["public_key"]})
		if !ed25519.Verify(pubRaw, msg, proof) {
			w.WriteHeader(400)
			return
		}
		f.renewed++
		f.grant(w, req["public_key"], "")
	default:
		w.WriteHeader(404)
	}
}

func setup(t *testing.T) (*fakeKEEN, *httptest.Server) {
	f := &fakeKEEN{t: t, keys: map[string]ed25519.PublicKey{}, nonces: map[string]string{}, proofs: map[string]bool{}}
	s := httptest.NewTLSServer(f)
	t.Cleanup(s.Close)
	return f, s
}

func TestCodeEnrolmentAndRenewal(t *testing.T) {
	f, s := setup(t)
	store := &memoryStore{}
	endpoint := s.URL + "/api/v1/otlp/logs"
	id, err := Open(store, endpoint, "")
	if err != nil || id.Enrolled() || store.saves != 1 {
		t.Fatal(id, err)
	}
	code := "kc_" + agentID + "." + strings.Repeat("A", 43)
	m := NewManager(store, id, s.Client(), "test", func() (string, error) { return code, nil })
	ready, err := m.Ready(context.Background(), time.Now())
	if err != nil || !ready || !m.Identity().Enrolled() || f.enrolled != 1 {
		t.Fatal(ready, err)
	}
	if m.Identity().EvidenceCeiling() != ueu.ModeEventsAndLines || m.Identity().SubjectType != "pairwise" {
		t.Fatal(m.Identity())
	}
	if err = m.Identity().Validate(); err != nil {
		t.Fatal(err)
	}
	firstKey := m.Identity().KeyID
	// Renewal is due: the current key signs, the new key proves possession.
	ready, err = m.Ready(context.Background(), m.Identity().RenewAt.Add(time.Second))
	if err != nil || !ready || f.renewed != 1 || m.Identity().KeyID == firstKey || m.Identity().RenewalNonce != "" {
		t.Fatal(ready, err)
	}
	pairwise := m.Identity().PairwiseKey
	if pairwise == "" || store.id.PairwiseKey != pairwise {
		t.Fatal("pairwise subject key must survive renewal")
	}
}

func TestEveryEnrolmentAttemptSignsAFreshProof(t *testing.T) {
	f, s := setup(t)
	id, err := New(s.URL + "/api/v1/otlp/logs")
	if err != nil {
		t.Fatal(err)
	}
	code := "kc_" + agentID + "." + strings.Repeat("A", 43)
	// A retry after a lost response repeats the request with a new proof,
	// which the fake server, like KEEN, requires.
	for range 2 {
		if _, err := Enroll(context.Background(), s.Client(), id, code, "test"); err != nil {
			t.Fatal(err)
		}
	}
	if f.enrolled != 2 || len(f.proofs) != 2 {
		t.Fatal(f.enrolled, f.proofs)
	}
}

func TestProfileEnrolmentPersistsNonceBeforeRequest(t *testing.T) {
	f, s := setup(t)
	store := &memoryStore{}
	id, _ := Open(store, s.URL+"/api/v1/otlp/logs", "host-1")
	key := "ke_" + agentID + "." + strings.Repeat("B", 43)
	f.status = 503
	m := NewManager(store, id, s.Client(), "test", func() (string, error) { return key, nil })
	if ready, _ := m.Ready(context.Background(), time.Now()); ready {
		t.Fatal("ready while KEEN unavailable")
	}
	nonce := store.id.EnrollmentNonce
	if nonce == "" || store.id.ProfileID != agentID || store.id.NextAttempt.IsZero() {
		t.Fatal("nonce or backoff not persisted")
	}
	f.status = 0
	ready, err := m.Ready(context.Background(), time.Now().Add(time.Hour))
	if err != nil || !ready || f.nonces[nonce] == "" {
		t.Fatal(ready, err)
	}
}

func TestPermanentRejectionBlocks(t *testing.T) {
	f, s := setup(t)
	store := &memoryStore{}
	id, _ := Open(store, s.URL+"/api/v1/otlp/logs", "")
	f.status = 401
	m := NewManager(store, id, s.Client(), "test", func() (string, error) { return "kc_" + agentID + "." + strings.Repeat("C", 43), nil })
	if ready, err := m.Ready(context.Background(), time.Now()); ready || err == nil || store.id.Blocked == "" {
		t.Fatal("permanent rejection did not block")
	}
	if ready, _ := m.Ready(context.Background(), time.Now().Add(24*time.Hour)); ready {
		t.Fatal("blocked identity became ready")
	}
	if err := m.Unblock(); err != nil || store.id.Blocked != "" {
		t.Fatal(err)
	}
}

func TestAcceptRejectsAForeignKey(t *testing.T) {
	id, _ := New("https://keen.example/api/v1/otlp/logs")
	other, _ := New("https://keen.example/api/v1/otlp/logs")
	otherKey, _ := other.Key()
	var g Grant
	g.Agent.ID, g.Agent.Name, g.Agent.Enabled = agentID, "host-1", true
	g.Agent.ExpiresAt = time.Now().Add(time.Hour).Format(time.RFC3339)
	g.KeyID = ueu.KeyID(agentID, otherKey.Public().(ed25519.PublicKey))
	g.Subject.Type, g.Ceiling = "pairwise", "events"
	if err := id.Accept(g, id.PrivateKey, time.Now()); err == nil {
		t.Fatal("accepted a grant for another key")
	}
	g.Subject.Type = "public"
	key, _ := id.Key()
	g.KeyID = ueu.KeyID(agentID, key.Public().(ed25519.PublicKey))
	if err := id.Accept(g, id.PrivateKey, time.Now()); err == nil {
		t.Fatal("accepted a public subject without a key")
	}
	g.Subject.Key = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if err := id.Accept(g, id.PrivateKey, time.Now()); err != nil || id.SubjectType != "public" {
		t.Fatal(err)
	}
}

func TestPersistenceFailureIsReported(t *testing.T) {
	store := &memoryStore{fail: true}
	if _, err := Open(store, "https://keen.example/api/v1/otlp/logs", ""); !errors.As(err, new(PersistenceError)) {
		t.Fatal(err)
	}
}

func TestFileStoreIsPrivateAndAtomic(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	store := FileStore{Dir: dir}
	if _, err := store.Load(); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	id, _ := New("https://keen.example/api/v1/otlp/logs")
	if err := store.Save(id); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || got.PrivateKey != id.PrivateKey {
		t.Fatal(err)
	}
	st, _ := os.Stat(dir + "/" + IdentityFile)
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	os.Chmod(dir, 0755)
	if _, err = store.Load(); err == nil {
		t.Fatal("loaded from a shared directory")
	}
}
