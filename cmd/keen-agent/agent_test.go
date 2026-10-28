package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keen-agent/internal/agentauth"

	bolt "go.etcd.io/bbolt"
	"keen-agent/internal/ueu"
)

const testAgentID = "6f8459a2-2768-41a4-94d5-a0cdcc2d7187"

// testIdentity is an enrolled identity whose KEEN ceiling allows all modes.
func testIdentity(t *testing.T, endpoint string) agentauth.Identity {
	t.Helper()
	id, err := agentauth.New(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := id.Key()
	id.AgentID, id.Name, id.AssetType = testAgentID, "host-1", "server"
	id.KeyID = ueu.KeyID(testAgentID, priv.Public().(ed25519.PublicKey))
	id.ExpiresAt, id.RenewAt = time.Now().Add(90*24*time.Hour), time.Now().Add(80*24*time.Hour)
	id.SubjectType, id.Ceiling = "pairwise", "all_lines"
	if err = id.Validate(); err != nil {
		t.Fatal(err)
	}
	return id
}

// testSpool is enrolled; sources default to all_lines so plain lines are evidence.
func testSpool(t *testing.T) *Spool {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, e := openSpool(dir, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.db.Close() })
	if s.sealer, e = newSealer(Config{EvidenceMode: "all_lines"}, testIdentity(t, "https://keen.example/api/v1/otlp/logs")); e != nil {
		t.Fatal(e)
	}
	return s
}

func event() Event {
	return Event{Timestamp: time.Now().UTC(), Source: "test", Action: "test", Outcome: "info", Summary: "test", Raw: "test", Fields: map[string]string{}}
}

var rawSource = Source{Name: "test", Parser: "raw"}

// envelopesFor classifies events through a spool's sealer.
func envelopesFor(t *testing.T, s *Spool, src Source, events ...Event) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, e := range events {
		envs, err := s.sealer.envelopes(src, e)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, envs...)
	}
	return out
}

func decoded(t *testing.T, r record) map[string]any {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal([]byte(r.Canonical), &env); err != nil {
		t.Fatal(err)
	}
	return env
}

func payload(t *testing.T, r record) string {
	p, _ := decoded(t, r)["evidence"].(map[string]any)["payload"].(string)
	return p
}

func TestQueueAndCheckpointAtomic(t *testing.T) {
	s := testSpool(t)
	if err := s.add(envelopesFor(t, s, rawSource, event()), "file", Checkpoint{Offset: 10}); err != nil {
		t.Fatal(err)
	}
	s.limit = 1
	if err := s.add(envelopesFor(t, s, rawSource, event()), "file", Checkpoint{Offset: 20}); err != full {
		t.Fatal(err)
	}
	var state Checkpoint
	s.checkpoint("file", &state)
	if state.Offset != 10 || s.chainPosition() != 1 {
		t.Fatal("failed transaction advanced the checkpoint or chain", state, s.chainPosition())
	}
	b, _ := s.batch()
	if len(b) != 1 || b[0].Sequence != 1 || ueu.HashEnvelope([]byte(b[0].Canonical)) != b[0].Hash {
		t.Fatal(b)
	}
	s.ack(map[string]bool{b[0].EvidenceID: true})
	if n, _, _ := s.stats(); n != 0 {
		t.Fatal(n)
	}
}

func TestUpgradeSealsRecordsQueuedByEarlierVersions(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := openSpool(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	// Two records as KEEN Agent 0.1 queued them, one from a source since removed.
	for _, source := range []string{"test", "removed"} {
		e := event()
		e.Source = source
		b, _ := json.Marshal(map[string]any{
			"event": map[string]any{"agent_version": "0.1.6", "id": "6f1c0f5e-2b0e-4a52-9a43-7c1f4b8f2d11", "timestamp": e.Timestamp, "source": e.Source, "action": e.Action, "outcome": e.Outcome, "severity": 3, "summary": e.Summary, "raw": e.Raw, "fields": e.Fields},
			"added": time.Now().UTC(),
		})
		if err := s.db.Update(func(tx *bolt.Tx) error {
			m := tx.Bucket(meta)
			seq, _ := tx.Bucket(q).NextSequence()
			k := make([]byte, 8)
			binary.BigEndian.PutUint64(k, seq)
			putInt(m, "bytes", integer(m.Get([]byte("bytes")))+int64(len(b)))
			putInt(m, "count", integer(m.Get([]byte("count")))+1)
			return tx.Bucket(q).Put(k, b)
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Nothing changes before enrolment.
	if n, err := s.upgradeQueue([]Source{rawSource}); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	s.sealer, _ = newSealer(Config{EvidenceMode: "all_lines"}, testIdentity(t, "https://keen.example/api/v1/otlp/logs"))
	n, err := s.upgradeQueue([]Source{rawSource})
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	records, _ := s.batch()
	if len(records) != 2 || records[0].Sequence != 1 || records[1].Sequence != 2 {
		t.Fatal(records)
	}
	for _, r := range records {
		if r.EventType != "log.line.collected" || decoded(t, r)["integrity"] == nil {
			t.Fatal(r)
		}
	}
	count, size, _ := s.stats()
	var stored int64
	s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(q).ForEach(func(_, v []byte) error { stored += int64(len(v)); return nil })
	})
	if count != 2 || size != stored {
		t.Fatal(count, size, stored)
	}
	// A second pass finds nothing left to upgrade.
	if n, err := s.upgradeQueue([]Source{rawSource}); n != 0 || err != nil {
		t.Fatal(n, err)
	}
}

func TestRestartKeepsSealedRecordAndChain(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, _ := openSpool(dir, 1<<20)
	s.sealer, _ = newSealer(Config{EvidenceMode: "all_lines"}, testIdentity(t, "https://keen.example/api/v1/otlp/logs"))
	s.add(envelopesFor(t, s, rawSource, event()), "file", Checkpoint{Offset: 99})
	sealer := s.sealer
	s.db.Close()
	s, _ = openSpool(dir, 1<<20)
	defer s.db.Close()
	s.sealer = sealer
	first, _ := s.batch()
	s.add(envelopesFor(t, s, rawSource, event()), "", nil)
	both, _ := s.batch()
	if len(both) != 2 || both[0].Canonical != first[0].Canonical || both[1].Sequence != 2 {
		t.Fatal("sealed record changed or chain restarted after restart")
	}
	integrity := decoded(t, both[1])["integrity"].(map[string]any)
	if integrity["previous_evidence_hash"] != both[0].Hash {
		t.Fatal("chain link lost across restart")
	}
}

func TestRotationAndPartialLine(t *testing.T) {
	s := testSpool(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "log")
	os.WriteFile(path, []byte("first\npartial"), 0600)
	c := Config{}
	if e := collectFile(c, rawSource, s, path); e != nil {
		t.Fatal(e)
	}
	b, _ := s.batch()
	if len(b) != 1 {
		t.Fatal(len(b))
	}
	os.Rename(path, path+".1")
	os.WriteFile(path, []byte("new\n"), 0600)
	collectFile(c, rawSource, s, path)
	f, _ := os.OpenFile(path+".1", os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(" complete\n")
	f.Close()
	collectFile(c, rawSource, s, path+".1")
	b, _ = s.batch()
	if len(b) != 3 || payload(t, b[2]) != "partial complete" {
		t.Fatal(b)
	}
	ref := decoded(t, b[2])["evidence"].(map[string]any)["supporting_record_reference"].(string)
	if !strings.HasPrefix(ref, "file:"+path+".1@") {
		t.Fatal(ref)
	}
}

func TestAuditInterleavingAndOutcome(t *testing.T) {
	st := Checkpoint{}
	s := Source{Name: "audit", Parser: "auditd"}
	now := time.Now()
	groups(Config{}, s, &st, "type=SYSCALL msg=audit(1791240000.001:12): success=no auid=1000", now)
	groups(Config{}, s, &st, "type=SYSCALL msg=audit(1791240000.002:13): success=yes", now)
	out, _ := groups(Config{}, s, &st, "type=EOE msg=audit(1791240000.001:12):", now)
	if len(out) != 1 || out[0].Outcome != "failure" || out[0].Fields["audit_id"] != "1791240000.001:12" {
		t.Fatal(out)
	}
	if len(st.Groups) != 1 {
		t.Fatal(st)
	}
}

// fakeReceiver verifies request and batch signatures as KEEN does.
type fakeReceiver struct {
	t       *testing.T
	pub     ed25519.PublicKey
	keyID   string
	bodies  [][]string
	replies []func(http.ResponseWriter)
}

func (f *fakeReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	lookup := func(k string) (ed25519.PublicKey, error) {
		if k != f.keyID {
			return nil, errors.New("unknown key")
		}
		return f.pub, nil
	}
	if _, err := ueu.VerifyRequest(r.Header, r.Method, ueu.OperationLogs, body, lookup, time.Now()); err != nil {
		f.t.Errorf("request signature: %v", err)
		w.WriteHeader(401)
		return
	}
	var doc struct {
		ResourceLogs []struct {
			Resource struct {
				Attributes []struct {
					Key   string            `json:"key"`
					Value map[string]string `json:"value"`
				} `json:"attributes"`
			} `json:"resource"`
			ScopeLogs []struct {
				LogRecords []struct {
					Body map[string]string `json:"body"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	json.Unmarshal(body, &doc)
	attrs := map[string]string{}
	for _, a := range doc.ResourceLogs[0].Resource.Attributes {
		attrs[a.Key] = a.Value["stringValue"]
	}
	if err := ueu.VerifyManifest(f.pub, []byte(attrs[ueu.AttrManifest]), attrs[ueu.AttrSignature]); err != nil {
		f.t.Errorf("manifest signature: %v", err)
	}
	var envelopes []string
	for _, r := range doc.ResourceLogs[0].ScopeLogs[0].LogRecords {
		envelopes = append(envelopes, r.Body["stringValue"])
		if !strings.Contains(attrs[ueu.AttrManifest], ueu.HashEnvelope([]byte(r.Body["stringValue"]))) {
			f.t.Error("record not covered by the signed manifest")
		}
	}
	f.bodies = append(f.bodies, envelopes)
	reply := f.replies[min(len(f.bodies)-1, len(f.replies)-1)]
	reply(w)
}

func receiver(t *testing.T, id agentauth.Identity, replies ...func(http.ResponseWriter)) (*fakeReceiver, *httptest.Server) {
	priv, _ := id.Key()
	f := &fakeReceiver{t: t, pub: priv.Public().(ed25519.PublicKey), keyID: id.KeyID, replies: replies}
	s := httptest.NewTLSServer(f)
	t.Cleanup(s.Close)
	return f, s
}

func status(code int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.WriteHeader(code) }
}
func ack(body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.Write([]byte(body)) }
}

func TestLostAckReplaysTheSameEvidence(t *testing.T) {
	s := testSpool(t)
	s.add(envelopesFor(t, s, rawSource, event(), event()), "", nil)
	id := testIdentity(t, "")
	f, server := receiver(t, id, status(503), ack("{}"))
	id.Endpoint = server.URL + "/api/v1/otlp/logs"
	c := Config{Endpoint: id.Endpoint}
	if send(c, s, server.Client(), id) == nil {
		t.Fatal("expected retry")
	}
	if err := send(c, s, server.Client(), id); err != nil {
		t.Fatal(err)
	}
	if len(f.bodies) != 2 || strings.Join(f.bodies[0], "") != strings.Join(f.bodies[1], "") {
		t.Fatal("retried evidence changed")
	}
	if n, _, _ := s.stats(); n != 0 {
		t.Fatal(n)
	}
}

func TestPermanentRejectionKeepsRecords(t *testing.T) {
	s := testSpool(t)
	s.add(envelopesFor(t, s, rawSource, event()), "", nil)
	id := testIdentity(t, "")
	_, server := receiver(t, id, status(401))
	id.Endpoint = server.URL + "/api/v1/otlp/logs"
	err := send(Config{Endpoint: id.Endpoint}, s, server.Client(), id)
	var de deliveryError
	if !errors.As(err, &de) || de.status != 401 {
		t.Fatal(err)
	}
	if n, _, _ := s.stats(); n != 1 {
		t.Fatal("rejected records discarded")
	}
}

func TestInvalidOrPartialAckRetainsRecords(t *testing.T) {
	for _, body := range []string{"null", "not-json", `{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"invalid"}}`} {
		t.Run(body, func(t *testing.T) {
			s := testSpool(t)
			s.add(envelopesFor(t, s, rawSource, event()), "", nil)
			id := testIdentity(t, "")
			_, server := receiver(t, id, ack(body))
			id.Endpoint = server.URL + "/api/v1/otlp/logs"
			if err := send(Config{Endpoint: id.Endpoint}, s, server.Client(), id); err == nil {
				t.Fatal("bad acknowledgement accepted")
			}
			if n, _, _ := s.stats(); n != 1 {
				t.Fatal("record discarded")
			}
		})
	}
}

func TestBoundedOversizeAndNextLine(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 4*1024*1024)+"\nok\npartial"), 4096)
	line, n, large, err := boundedLine(r)
	if err != nil || !large || line != "" || n != 4*1024*1024+1 {
		t.Fatal(n, large, err)
	}
	line, _, large, err = boundedLine(r)
	if line != "ok\n" || large || err != nil {
		t.Fatal(line, large, err)
	}
	if _, _, _, err = boundedLine(r); err != io.EOF {
		t.Fatal(err)
	}
}

func TestCredentialsSymlinkAndWorldReadableRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "code")
	os.WriteFile(path, []byte("secret"), 0644)
	if _, err := readPrivate(path, 4096, true); err == nil {
		t.Fatal("world-readable credential accepted")
	}
	os.Chmod(path, 0600)
	os.Symlink(path, path+"-link")
	if _, err := readPrivate(path+"-link", 4096, true); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestTLSAndRedirectProtection(t *testing.T) {
	sinkCalls := 0
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sinkCalls++; w.Write([]byte("{}")) }))
	defer sink.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, sink.URL, 307) }))
	defer redirect.Close()
	h, _ := client(Config{})
	if _, err := h.Get(redirect.URL); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	h.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
	h.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(redirect.Certificate())
	if _, err := h.Get(redirect.URL); err == nil {
		t.Fatal("redirect accepted")
	}
	if sinkCalls != 0 {
		t.Fatal("followed redirect")
	}
}

const testConfig = "endpoint: https://keen.example/api/v1/otlp/logs\nenrollment:\n  code_file: /etc/keen-agent/enrollment-code\nsources:\n"

func writeConfig(t *testing.T, text string) string {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigRedactionAndEqualFilters(t *testing.T) {
	c, err := config(writeConfig(t, testConfig+"  - name: test\n    kind: journal\n    parser: raw\n    include: same\n    exclude: same\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Sources[0].include == nil || c.Sources[0].exclude == nil {
		t.Fatal("equal regex collision")
	}
	for _, raw := range []string{`{"password":"my-value"}`, "Authorization: Bearer my-value", "token=my-value", "password: my-value", "API_KEY = 'my-value'"} {
		if strings.Contains(c.redact(raw), "my-value") {
			t.Fatal("secret survived redaction")
		}
	}
	// SSH authentication messages name the method; they must stay recognisable.
	line := "2026-10-27T09:01:05+00:00 web01 sshd[1235]: Failed password for bob from 192.0.2.11 port 50001 ssh2"
	if got := c.redact(line); got != line {
		t.Fatalf("redaction changed an SSH message: %s", got)
	}
	src := Source{Name: "auth", Kind: "file", Parser: "syslog"}
	e := parse(c, src, line, time.Now())
	r := recognise(src, e)
	if r == nil || r.eventType != "user.authenticated" || r.subject != "bob" {
		t.Fatalf("failed SSH password login not recognised: %+v %+v", e, r)
	}
}

func TestEnrollmentAndEvidenceModeConfiguration(t *testing.T) {
	source := "  - name: journal\n    kind: journal\n    parser: syslog\n"
	for name, tc := range map[string]struct {
		text  string
		valid bool
	}{
		"code":           {testConfig + source, true},
		"bootstrap":      {"endpoint: https://keen.example/api/v1/otlp/logs\nenrollment:\n  bootstrap_key_file: /etc/keen-agent/bootstrap\n  name: web-01\nsources:\n" + source, true},
		"both":           {"endpoint: https://keen.example/api/v1/otlp/logs\nenrollment:\n  code_file: /a\n  bootstrap_key_file: /b\nsources:\n" + source, false},
		"preenrolled":    {"endpoint: https://keen.example/api/v1/otlp/logs\nsources:\n" + source, true},
		"relative":       {"endpoint: https://keen.example/api/v1/otlp/logs\nenrollment:\n  code_file: code\nsources:\n" + source, false},
		"token_file":     {testConfig + source + "token_file: /etc/keen-agent/token\n", false},
		"mode":           {"evidence_mode: events_with_lines\n" + testConfig + source + "    evidence_mode: all_lines\n", true},
		"unknown_mode":   {"evidence_mode: everything\n" + testConfig + source, false},
		"source_unknown": {testConfig + source + "    evidence_mode: some\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := config(writeConfig(t, tc.text)); (err == nil) != tc.valid {
				t.Fatal(err)
			}
		})
	}
}

func TestEarlierTokenConfigurationExplainsTheUpgrade(t *testing.T) {
	text := "endpoint: https://keen.example/api/v1/otlp/logs\ntoken_file: /etc/keen-agent/token\nsources:\n  - name: journal\n    kind: journal\n    parser: syslog\n"
	_, err := config(writeConfig(t, text))
	if err == nil || !strings.Contains(err.Error(), "enrollment.code_file") {
		t.Fatal(err)
	}
}

func TestAuditPendingSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, _ := openSpool(dir, 1<<20)
	st := Checkpoint{}
	src := Source{Name: "audit", Parser: "auditd"}
	now := time.Now()
	groups(Config{}, src, &st, "type=SYSCALL msg=audit(1791240000.001:55): success=no", now)
	s.add(nil, "audit", st)
	s.db.Close()
	s, _ = openSpool(dir, 1<<20)
	defer s.db.Close()
	var restored Checkpoint
	s.checkpoint("audit", &restored)
	out, err := groups(Config{}, src, &restored, "type=EOE msg=audit(1791240000.001:55):", now)
	if err != nil || len(out) != 1 || out[0].Action != "auditd.SYSCALL" || out[0].Outcome != "failure" {
		t.Fatal(out, err)
	}
}

func TestCopyTruncateDetected(t *testing.T) {
	s := testSpool(t)
	path := filepath.Join(t.TempDir(), "log")
	os.WriteFile(path, []byte("first-record\n"), 0600)
	collectFile(Config{}, rawSource, s, path)
	os.WriteFile(path, []byte("new\n"), 0600)
	collectFile(Config{}, rawSource, s, path)
	n, _, gaps := s.stats()
	if n != 2 || gaps != 1 {
		t.Fatal(n, gaps)
	}
}

func TestPendingGroupsCountAgainstCapacity(t *testing.T) {
	s := testSpool(t)
	s.limit = 1024
	if err := s.add(nil, "pending", Checkpoint{Groups: map[string]Pending{"a": {Raw: strings.Repeat("x", 500)}}}); err != full {
		t.Fatal("pending data escaped budget", err)
	}
	var state Checkpoint
	s.checkpoint("pending", &state)
	if len(state.Groups) != 0 {
		t.Fatal("failed checkpoint committed")
	}
}

func TestUnenrolledSpoolRefusesEvidence(t *testing.T) {
	s := testSpool(t)
	envs := envelopesFor(t, s, rawSource, event())
	s.sealer = nil
	if err := s.add(envs, "", nil); err == nil {
		t.Fatal("sealed without an identity")
	}
	if err := s.addFiltered(rawSource, []Event{event()}, "", nil); err == nil {
		t.Fatal("classified without an identity")
	}
}

func TestMissingIdentityAfterEvidenceStops(t *testing.T) {
	s := testSpool(t)
	s.add(envelopesFor(t, s, rawSource, event()), "", nil)
	c := Config{Endpoint: "https://keen.example/api/v1/otlp/logs", StateDir: t.TempDir()}
	os.Chmod(c.StateDir, 0700)
	if _, err := openManager(c, s, http.DefaultClient); err == nil || !strings.Contains(err.Error(), "identity is missing") {
		t.Fatal(err)
	}
	fresh := testSpool(t)
	if _, err := openManager(c, fresh, http.DefaultClient); err != nil {
		t.Fatal("first enrolment refused", err)
	}
}
