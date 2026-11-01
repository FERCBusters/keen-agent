package agentauth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"keen-agent/internal/keentest"
	"keen-agent/internal/ueu"
)

func enrolledManager(t *testing.T) (*fakeKEEN, *httptest.Server, *Manager, *memoryStore) {
	t.Helper()
	f, s := setup(t)
	store := &memoryStore{}
	id, _ := Open(store, s.URL+"/api/v1/otlp/logs", "")
	m := NewManager(store, id, s.Client(), "test", func() (string, error) { return f.keen.Credential("kc", agentID), nil })
	if ready, err := m.Ready(context.Background(), time.Now()); !ready || err != nil {
		t.Fatal(ready, err)
	}
	return f, s, m, store
}

func mutate(doc []byte, change func(map[string]any)) []byte {
	var v map[string]any
	json.Unmarshal(doc, &v)
	change(v)
	out, _ := json.Marshal(v)
	return out
}

func TestServerKeyDocumentIsCheckedAgainstThePin(t *testing.T) {
	k := keentest.New()
	now := time.Now()
	good, err := VerifyServerKey(k.Document(), k.Fingerprint, now)
	if err != nil || good.EncryptionKey != k.Current || good.Identity != k.Fingerprint || good.Validate() != nil {
		t.Fatal(good, err)
	}
	other := keentest.New()
	cases := map[string][]byte{
		"another KEEN":  other.Document(),
		"unknown field": mutate(k.Document(), func(v map[string]any) { v["extra"] = 1 }),
		"swapped key": mutate(k.Document(), func(v map[string]any) {
			v["encryption_key"].(map[string]any)["public_key"] = json.RawMessage(nil)
			v["encryption_key"] = mutate(other.Document(), func(map[string]any) {})
		}),
		"altered statement": mutate(k.Document(), func(v map[string]any) {
			v["encryption_key"].(map[string]any)["not_after"] = "2099-01-01T00:00:00Z"
		}),
		"extra statement field": mutate(k.Document(), func(v map[string]any) {
			v["encryption_key"].(map[string]any)["note"] = "x"
		}),
		"missing statement field": mutate(k.Document(), func(v map[string]any) {
			delete(v["encryption_key"].(map[string]any), "kem")
		}),
		"bad signature": mutate(k.Document(), func(v map[string]any) { v["signature"] = "AAAA" }),
		"not json":      []byte("{"),
		"bad identity":  mutate(k.Document(), func(v map[string]any) { v["identity"].(map[string]any)["public_key"] = "AAAA" }),
	}
	for name, doc := range cases {
		if _, err := VerifyServerKey(doc, k.Fingerprint, now); err == nil {
			t.Error(name, "accepted")
		}
	}
	if _, err := VerifyServerKey(k.Document(), other.Fingerprint, now); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatal(err)
	}
	if _, err := VerifyServerKey(k.Document(), k.Fingerprint, now.Add(366*24*time.Hour)); err == nil {
		t.Fatal("expired key accepted")
	}
	// A statement signed by the identity but naming an unsupported suite.
	k.Rotate(now.Add(time.Hour))
	var doc map[string]any
	json.Unmarshal(k.Document(), &doc)
	statement := doc["encryption_key"].(map[string]any)
	statement["kem"] = "X25519"
	canonical, _ := ueu.Canonical(statement)
	doc["signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.Identity, canonical))
	resigned, _ := json.Marshal(doc)
	if _, err := VerifyServerKey(resigned, k.Fingerprint, now); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatal(err)
	}
}

func TestCredentialsCarryThePin(t *testing.T) {
	k := keentest.New()
	if fp, err := CredentialFingerprint(" " + k.Credential("kc", agentID) + "\n"); err != nil || fp != k.Fingerprint {
		t.Fatal(fp, err)
	}
	if _, err := CredentialFingerprint("kc_" + agentID + "." + strings.Repeat("A", 43)); err == nil {
		t.Fatal("a credential without a pin was accepted")
	}
	if _, err := ReadCredential([]byte("ka_" + agentID + "." + strings.Repeat("A", 43))); err == nil {
		t.Fatal("token accepted as a credential")
	}
	if _, err := ReadCredential([]byte("kc_" + agentID + "." + strings.Repeat("A", 43))); err == nil || !strings.Contains(err.Error(), "issue a new one") {
		t.Fatal("a code without KEEN's fingerprint must say why it is refused", err)
	}
}

func TestAnImpostorWithACertificateNeverSeesTheCredential(t *testing.T) {
	// The impostor holds a valid certificate for the endpoint, but not KEEN's
	// identity key: the agent stops at the server-key document.
	real := keentest.New()
	impostor, s := setup(t)
	id, _ := New(s.URL + "/api/v1/otlp/logs")
	_, _, err := Enroll(context.Background(), s.Client(), id, real.Credential("kc", agentID), "test")
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatal(err)
	}
	if len(impostor.paths) != 1 || impostor.paths[0] != "/api/v1/agents/server-key" || impostor.enrolled != 0 {
		t.Fatal(impostor.paths)
	}
}

func TestUnsealedOrForeignAnswersChangeNothing(t *testing.T) {
	for _, answer := range []string{`{}`, strings.Repeat("A", 64)} {
		f, s, m, store := enrolledManager(t)
		before := *store.id
		f.impostor = answer
		_, err := m.Post(context.Background(), s.URL+"/api/v1/otlp/logs", ueu.OperationLogs, []byte(`{}`))
		if !errors.As(err, new(UntrustedResponse)) {
			t.Fatal(err)
		}
		// A forged renewal grant is never applied: the pending renewal stays.
		ready, err := m.Ready(context.Background(), m.Identity().RenewAt.Add(time.Second))
		if ready || !errors.As(err, new(UntrustedResponse)) || store.id.KeyID != before.KeyID || store.id.RenewalNonce == "" || store.id.Blocked != "" {
			t.Fatal(ready, err, store.id)
		}
		// Once KEEN answers again, the same renewal completes.
		f.impostor = ""
		ready, err = m.Ready(context.Background(), store.id.NextAttempt.Add(time.Second))
		if !ready || err != nil || store.id.KeyID == before.KeyID || f.renewed != 1 {
			t.Fatal(ready, err)
		}
	}
}

func TestPlaintextSuccessIsNotTrusted(t *testing.T) {
	_, s, m, _ := enrolledManager(t)
	plain := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer plain.Close()
	m.Client = plain.Client()
	_, err := m.Post(context.Background(), plain.URL+"/api/v1/otlp/logs", ueu.OperationLogs, []byte(`{}`))
	if !errors.As(err, new(UntrustedResponse)) || !strings.Contains(err.Error(), "not sealed") {
		t.Fatal(err)
	}
	_ = s
}

func TestRotationAndRefusedKeysAreFollowed(t *testing.T) {
	f, s, m, store := enrolledManager(t)
	url := s.URL + "/api/v1/otlp/logs"
	var seen []string
	handler := s.Config.Handler
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path+" "+r.Header.Get("Keen-Encryption-Key"))
		if r.URL.Path == "/api/v1/otlp/logs" {
			body, _ := io.ReadAll(r.Body)
			o, refused := f.keen.Open(r, body, ueu.OperationLogs, m.Identity().KeyID)
			if refused != 0 {
				w.WriteHeader(refused)
				return
			}
			f.keen.Reply(w, o, 200, []byte(`{}`))
			return
		}
		handler.ServeHTTP(w, r)
	})
	// KEEN rotates; its next response names the new key; the agent fetches
	// and verifies it before its next request.
	first := store.id.Server.EncryptionKey
	second := f.keen.Rotate(time.Now().Add(37 * 24 * time.Hour))
	if _, err := m.Post(context.Background(), url, ueu.OperationLogs, []byte(`{}`)); err != nil || !m.refresh {
		t.Fatal(err)
	}
	if ready, err := m.Ready(context.Background(), time.Now()); !ready || err != nil || store.id.Server.EncryptionKey != second {
		t.Fatal(ready, err, first)
	}
	// KEEN erased the key the agent holds: 421, one fetch, one retry.
	third := f.keen.Rotate(time.Now().Add(37 * 24 * time.Hour))
	f.keen.Forget(second)
	m.lastFetch = m.lastFetch.Add(-2 * keyFetchSpacing)
	seen = nil
	res, err := m.Post(context.Background(), url, ueu.OperationLogs, []byte(`{}`))
	if err != nil || string(res.Body) != "{}" || store.id.Server.EncryptionKey != third {
		t.Fatal(err, seen)
	}
	if len(seen) != 3 || !strings.HasSuffix(seen[0], second) || !strings.HasPrefix(seen[1], "/api/v1/agents/server-key") || !strings.HasSuffix(seen[2], third) {
		t.Fatal(seen)
	}
	// Another 421 within the minute is returned without fetching again, so
	// a party answering 421 to everything cannot make the agent fetch on
	// every request; it does not block delivery either.
	f.keen.Forget(third)
	seen = nil
	_, err = m.Post(context.Background(), url, ueu.OperationLogs, []byte(`{}`))
	var rejected HTTPError
	if !NeedsKeyRefresh(err) || !errors.As(err, &rejected) || rejected.Permanent() || len(seen) != 1 {
		t.Fatal(err, seen)
	}
	// After the minute, a 421 is followed by one fetch and one retry.
	m.lastFetch = m.lastFetch.Add(-2 * keyFetchSpacing)
	seen = nil
	if _, err = m.Post(context.Background(), url, ueu.OperationLogs, []byte(`{}`)); !NeedsKeyRefresh(err) || len(seen) != 3 {
		t.Fatal(err, seen)
	}
}

func TestTheKeyIsFetchedAheadOfExpiryAndNotTooOften(t *testing.T) {
	f, s, m, store := enrolledManager(t)
	short := f.keen.Rotate(time.Now().Add(30 * 24 * time.Hour))
	m.refresh = true
	if ready, err := m.Ready(context.Background(), time.Now()); !ready || err != nil || store.id.Server.EncryptionKey != short {
		t.Fatal(ready, err)
	}
	near := store.id.Server.NotAfter.Add(-6 * 24 * time.Hour)
	next := f.keen.Rotate(time.Now().Add(60 * 24 * time.Hour))
	if ready, err := m.Ready(context.Background(), near); !ready || err != nil || store.id.Server.EncryptionKey != next {
		t.Fatal(ready, err)
	}
	// An hour's spacing for fetches ahead of expiry.
	fetches := func() (n int) {
		for _, p := range f.paths {
			if strings.HasSuffix(p, "/server-key") {
				n++
			}
		}
		return
	}
	before := fetches()
	m.state.Server.NotAfter = near.Add(time.Hour)
	m.Ready(context.Background(), near.Add(time.Minute))
	if fetches() != before {
		t.Fatal("fetched again within the hour")
	}
	// A key that has expired with KEEN unreachable stops sending.
	f.status = 503
	m.Client = s.Client()
	expired := store.id.Server.NotAfter.Add(time.Hour)
	m.lastFetch = time.Time{}
	if ready, err := m.Ready(context.Background(), expired); ready || err == nil {
		t.Fatal("sent with an expired key")
	}
	if ready, err := m.Ready(context.Background(), expired.Add(time.Second)); ready || err == nil || !strings.Contains(err.Error(), "KEEN encryption key") {
		t.Fatal(ready, err)
	}
	if _, err := Post(context.Background(), s.Client(), s.URL, ueu.OperationLogs, nil, Identity{}, "test"); err == nil {
		t.Fatal("posted unenrolled")
	}
}

func TestAnEnrolledIdentityMustPinKEEN(t *testing.T) {
	_, _, m, _ := enrolledManager(t)
	id := m.Identity()
	if err := id.Validate(); err != nil {
		t.Fatal(err)
	}
	unpinned := id
	unpinned.Server = ServerKey{}
	if err := unpinned.Validate(); err == nil || !strings.Contains(err.Error(), "predates") {
		t.Fatal(err)
	}
	wrong := id
	wrong.Server.Identity = keentest.New().Fingerprint
	if err := wrong.Validate(); err == nil {
		t.Fatal("mismatched pin accepted")
	}
	bad := id
	bad.Server.PublicKey = "AAAA"
	if err := bad.Validate(); err == nil {
		t.Fatal("invalid encryption key accepted")
	}
	noKey := id
	noKey.Server.EncryptionKey, noKey.Server.PublicKey, noKey.Server.NotAfter = "", "", time.Time{}
	if err := noKey.Validate(); err != nil {
		t.Fatal("an identity may wait for KEEN's encryption key", err)
	}
}

func TestResponsesAreBoundToOperationAndStatus(t *testing.T) {
	o := keentest.Opened{ResponseKey: make([]byte, 32), Operation: "heartbeat"}
	sealed := keentest.SealResponse(o, 200, []byte(`{"ok":true}`))
	if plain, err := OpenResponse(o.ResponseKey, "heartbeat", 200, sealed); err != nil || string(plain) != `{"ok":true}` {
		t.Fatal(err)
	}
	for _, c := range []struct {
		op     string
		status int
		key    []byte
		body   []byte
	}{{"otlp-logs", 200, o.ResponseKey, sealed}, {"heartbeat", 201, o.ResponseKey, sealed}, {"heartbeat", 200, make([]byte, 31), sealed}, {"heartbeat", 200, o.ResponseKey, sealed[:20]}} {
		if _, err := OpenResponse(c.key, c.op, c.status, c.body); !errors.As(err, new(UntrustedResponse)) {
			t.Fatal(c.op, c.status, err)
		}
	}
}
