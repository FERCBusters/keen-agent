package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSpool(t *testing.T) *Spool {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, e := openSpool(dir, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.db.Close() })
	return s
}
func event() Event {
	return Event{ID: uuid(), Timestamp: time.Now().UTC(), Source: "test", Action: "test", Outcome: "info", Summary: "test", Raw: "test", Fields: map[string]string{}}
}
func TestQueueAndCheckpointAtomic(t *testing.T) {
	s := testSpool(t)
	e := event()
	if err := s.add([]Event{e}, "file", Checkpoint{Offset: 10}); err != nil {
		t.Fatal(err)
	}
	s.limit = 1
	if err := s.add([]Event{event()}, "file", Checkpoint{Offset: 20}); err != full {
		t.Fatal(err)
	}
	var state Checkpoint
	s.checkpoint("file", &state)
	if state.Offset != 10 {
		t.Fatal(state)
	}
	b, _ := s.batch()
	if len(b) != 1 || b[0].ID != e.ID {
		t.Fatal(b)
	}
	s.ack(map[string]bool{e.ID: true})
	n, _, _ := s.stats()
	if n != 0 {
		t.Fatal(n)
	}
}
func TestRestartRetainsIdentity(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, _ := openSpool(dir, 1<<20)
	e := event()
	s.add([]Event{e}, "file", Checkpoint{Offset: 99})
	s.db.Close()
	s, _ = openSpool(dir, 1<<20)
	defer s.db.Close()
	b, _ := s.batch()
	if b[0].ID != e.ID {
		t.Fatal("UUID changed")
	}
	var state Checkpoint
	s.checkpoint("file", &state)
	if state.Offset != 99 {
		t.Fatal(state)
	}
}
func TestRotationAndPartialLine(t *testing.T) {
	s := testSpool(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "log")
	os.WriteFile(path, []byte("first\npartial"), 0600)
	c := Config{}
	source := Source{Name: "test", Parser: "raw"}
	if e := collectFile(c, source, s, path); e != nil {
		t.Fatal(e)
	}
	b, _ := s.batch()
	if len(b) != 1 {
		t.Fatal(len(b))
	}
	os.Rename(path, path+".1")
	os.WriteFile(path, []byte("new\n"), 0600)
	collectFile(c, source, s, path)
	f, _ := os.OpenFile(path+".1", os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString(" complete\n")
	f.Close()
	collectFile(c, source, s, path+".1")
	b, _ = s.batch()
	if len(b) != 3 {
		t.Fatal(len(b))
	}
	if b[2].Raw != "partial complete" {
		t.Fatal(b[2])
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
func TestLostAckReplayAndRedirect(t *testing.T) {
	s := testSpool(t)
	e := event()
	s.add([]Event{e}, "", nil)
	calls := 0
	var first string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if calls == 0 {
			first = string(b)
			w.WriteHeader(503)
		} else {
			if first != string(b) {
				t.Error("retried payload changed")
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{}"))
		}
		calls++
	}))
	defer server.Close()
	token := filepath.Join(t.TempDir(), "token")
	os.WriteFile(token, []byte("ka_test"), 0600)
	c := Config{Endpoint: server.URL, TokenFile: token}
	if send(c, s, server.Client()) == nil {
		t.Fatal("expected retry")
	}
	if err := send(c, s, server.Client()); err != nil {
		t.Fatal(err)
	}
	n, _, _ := s.stats()
	if n != 0 {
		t.Fatal(n)
	}
}
func TestOTLPIdentity(t *testing.T) {
	e := event()
	var obj map[string]any
	if err := json.Unmarshal(otlp([]Event{e}), &obj); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(otlp([]Event{e})), e.ID) {
		t.Fatal("missing UUID")
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
	_, _, _, err = boundedLine(r)
	if err != io.EOF {
		t.Fatal(err)
	}
}
func TestCredentialsSymlinkAndWorldReadableRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
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
	c := Config{}
	h, _ := client(c)
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
func TestCanonicalAttributesOnRetry(t *testing.T) {
	e := event()
	e.Fields = map[string]string{"z": "last", "a": "first", "m": "middle"}
	first := string(otlp([]Event{e}))
	for i := 0; i < 50; i++ {
		if string(otlp([]Event{e})) != first {
			t.Fatal("unstable OTLP encoding")
		}
	}
}
func TestConfigRedactionAndEqualFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte("endpoint: https://keen.example/api/v1/otlp/logs\ntoken_file: /etc/keen-agent/token\nsources:\n  - name: test\n    kind: journal\n    parser: raw\n    include: same\n    exclude: same\n"), 0600)
	c, err := config(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sources[0].include == nil || c.Sources[0].exclude == nil {
		t.Fatal("equal regex collision")
	}
	for _, raw := range []string{`{"password":"my-value"}`, "Authorization: Bearer my-value", "token=my-value"} {
		if strings.Contains(c.redact(raw), "my-value") {
			t.Fatal("secret survived redaction")
		}
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

func TestInvalidOrPartialAckRetainsRecords(t *testing.T) {
	for _, ack := range []string{"null", "not-json", `{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"invalid"}}`} {
		t.Run(ack, func(t *testing.T) {
			s := testSpool(t)
			s.add([]Event{event()}, "", nil)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(ack)) }))
			defer server.Close()
			token := filepath.Join(t.TempDir(), "token")
			os.WriteFile(token, []byte("ka_test"), 0600)
			if err := send(Config{Endpoint: server.URL, TokenFile: token}, s, server.Client()); err == nil {
				t.Fatal("bad acknowledgement accepted")
			}
			n, _, _ := s.stats()
			if n != 1 {
				t.Fatal("record discarded")
			}
		})
	}
}
func TestCopyTruncateDetected(t *testing.T) {
	s := testSpool(t)
	path := filepath.Join(t.TempDir(), "log")
	src := Source{Name: "test", Parser: "raw"}
	os.WriteFile(path, []byte("first-record\n"), 0600)
	collectFile(Config{}, src, s, path)
	os.WriteFile(path, []byte("new\n"), 0600)
	collectFile(Config{}, src, s, path)
	n, _, gaps := s.stats()
	if n != 2 || gaps != 1 {
		t.Fatal(n, gaps)
	}
}

func TestCrossLanguageWireFixture(t *testing.T) {
	e := Event{ID: "6f8459a2-2768-41a4-94d5-a0cdcc2d7187", AgentVersion: "0.1.0", Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Source: "dpkg", Action: "package.upgrade", Outcome: "info", Severity: 3, Summary: "Example package upgrade", Raw: "2026-01-01 00:00:00 upgrade example:amd64 1.0 1.1", Fields: map[string]string{"parser": "dpkg", "package": "example:amd64", "old_version": "1.0", "new_version": "1.1"}}
	wire := otlp([]Event{e})
	if dest := os.Getenv("KEEN_WRITE_WIRE_FIXTURE"); dest != "" {
		if err := os.WriteFile(dest, wire, 0644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile("testdata/otlp.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(expected) != string(wire) {
		t.Fatal("wire format changed; update the cross-language fixture deliberately")
	}
}

func TestPendingGroupsCountAgainstCapacity(t *testing.T) {
 s:=testSpool(t);s.limit=1024
 err:=s.add(nil,"pending",Checkpoint{Groups:map[string]Pending{"a":{Raw:strings.Repeat("x",500)}}})
 if err!=full{t.Fatal("pending data escaped budget",err)}
 var state Checkpoint;s.checkpoint("pending",&state);if len(state.Groups)!=0{t.Fatal("failed checkpoint committed")}
}
