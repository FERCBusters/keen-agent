package nativeposture

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	bolt "go.etcd.io/bbolt"
	"io"
	"keen-agent/internal/agentauth"
	"keen-agent/internal/ueu"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner map[string]string

func (f fakeRunner) Run(_ context.Context, p string, a []string, _ []byte) ([]byte, error) {
	v, ok := f[p+" "+strings.Join(a, " ")]
	if !ok {
		return nil, errors.New("unavailable")
	}
	return []byte(v), nil
}
func TestMacDisabledAndConsoleUser(t *testing.T) {
	f := fakeRunner{
		"/usr/bin/fdesetup status": "FileVault is Off.",
		"/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate": "Firewall is disabled. (State = 0)",
		"/sbin/pfctl -s info":              "Status: Disabled",
		"/usr/bin/stat -f %u /dev/console": "501",
		"/usr/bin/sudo -n -H -u #501 -- /usr/bin/defaults -currentHost read com.apple.screensaver askForPassword": "0",
		"/usr/bin/defaults read /Library/Managed Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled":      "0",
		"/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled":              "1",
	}
	r := NewReport(CollectMac(context.Background(), f), true)
	got := map[string]Observation{}
	for _, o := range r.Observations {
		if e := o.Validate(); e != nil {
			t.Fatal(e)
		}
		got[o.Provider] = o
	}
	for _, p := range []string{"filevault", "macos_application_firewall", "macos_pf"} {
		if got[p].Facts["enabled"] != "false" {
			t.Fatalf("%s: %+v", p, got[p])
		}
	}
	if got["macos_screensaver"].Scope != "uid:501" || got["macos_screensaver"].Facts["password_required"] != "false" {
		t.Fatal(got)
	}
	if got["macos_software_update"].Facts["automatic_check_configured"] != "false" {
		t.Fatal("managed preference lost precedence")
	}
}
func TestMacTransitionNotPass(t *testing.T) {
	r := NewReport(CollectMac(context.Background(), fakeRunner{"/usr/bin/fdesetup status": "Encryption in progress: 32%"}), false)
	if len(r.Observations) != 1 || r.Observations[0].Facts["enabled"] != "" || r.Observations[0].Facts["transition_in_progress"] != "true" {
		t.Fatal(r)
	}
}
func TestDecodeStrict(t *testing.T) {
	o := observed("firewall", "windows_firewall", "Domain", "state_observed", map[string]string{"enabled": "false"})
	b, _ := json.Marshal([]Observation{o})
	if _, e := DecodeObservations(b); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{string(b) + " {}", `[{"version":1,"surprise":true}]`, "null {}"} {
		if _, e := DecodeObservations([]byte(bad)); e == nil {
			t.Fatal("accepted", bad)
		}
	}
	o.Facts["authority"] = "root"
	b, _ = json.Marshal([]Observation{o})
	if _, e := DecodeObservations(b); e == nil {
		t.Fatal("accepted forged authority")
	}
}
func TestRunEnvelopesAndCoverage(t *testing.T) {
	all := []Observation{
		unavailable("antivirus", "missing"),
		observed("firewall", "windows_firewall", "Public", "state_observed", map[string]string{"enabled": "false"}),
		observed("screen_lock", "windows_user_policy", "S-1-5-21-1-2-3-1001", "user_lock_settings_observed", map[string]string{"automatic_lock_configured": "true"}),
	}
	envs, err := Preview(all)
	if err != nil || len(envs) != 3 {
		t.Fatal(envs, err)
	}
	if envs[0]["event_type"] != "endpoint.firewall.observed" || envs[0]["observation"].(map[string]any)["facts"].(map[string]any)["enabled"] != false {
		t.Fatal(envs[0])
	}
	b, _ := ueu.Canonical(envs[1])
	if envs[1]["observation"].(map[string]any)["scope"] != "user" || strings.Contains(string(b), "S-1-5-21") {
		t.Fatal("account identifier sent")
	}
	coverage := envs[2]["attributes"].(map[string]any)
	got, _ := json.Marshal([]any{coverage["checks_unavailable"], coverage["probes_unavailable"]})
	if envs[2]["event_type"] != "evidence.collection.completed" || string(got) != `[["antivirus"],["antivirus/missing"]]` {
		t.Fatal(string(got))
	}
}
func TestAcknowledgement(t *testing.T) {
	for body, ok := range map[string]bool{`{}`: true, `{"partialSuccess":{"rejectedLogRecords":"0"}}`: true, `{"partialSuccess":{"rejectedLogRecords":"1"}}`: false, `null`: false, ``: false, `not json`: false, `{"partialSuccess":{"errorMessage":"error"}}`: false} {
		if (checkAck([]byte(body)) == nil) != ok {
			t.Fatal(body)
		}
	}
}

func TestQueueSignsRetriesAndAcknowledges(t *testing.T) {
	id, _ := agentauth.New("")
	priv, _ := id.Key()
	pub := priv.Public().(ed25519.PublicKey)
	id.AgentID, id.KeyID = "6f8459a2-2768-41a4-94d5-a0cdcc2d7187", ueu.KeyID("6f8459a2-2768-41a4-94d5-a0cdcc2d7187", pub)
	id.ExpiresAt, id.SubjectType, id.Ceiling = time.Now().Add(time.Hour), "pairwise", "events"
	db, e := bolt.Open(filepath.Join(t.TempDir(), "queue.db"), 0600, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	pr, _ := producer(id)
	envs, _ := Envelopes(pr, []Observation{observed("firewall", "pf", "host", "x", map[string]string{"enabled": "true"})}, time.Now())
	if e = seal(db, id.AgentID, envs); e != nil {
		t.Fatal(e)
	}
	fail := true
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if _, err := ueu.VerifyRequest(r.Header, "POST", ueu.OperationLogs, b, func(string) (ed25519.PublicKey, error) { return pub, nil }, time.Now()); err != nil {
			t.Error(err)
		}
		seen = append(seen, string(b))
		if fail {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	endpoint := server.URL + "/api/v1/otlp/logs"
	if e = flushQueue(context.Background(), db, server.Client(), endpoint, id); e == nil {
		t.Fatal("expected failure")
	}
	_, batch, _ := pending(db)
	if len(batch) != 2 {
		t.Fatal("failed delivery lost evidence")
	}
	fail = false
	if e = flushQueue(context.Background(), db, server.Client(), endpoint, id); e != nil {
		t.Fatal(e)
	}
	if _, batch, _ = pending(db); len(batch) != 0 || len(seen) != 2 {
		t.Fatal("queue not drained")
	}
	for _, s := range []string{seen[0], seen[1]} {
		if !strings.Contains(s, batch0(t, envs)) {
			t.Fatal("retry changed the evidence")
		}
	}
}

func batch0(t *testing.T, envs []map[string]any) string {
	return envs[0]["evidence_id"].(string)
}

func TestPowerCapabilitiesPrelude(t *testing.T) {
	caps := make([]byte, powerCapsSize)
	if got := powerCapabilitiesPrelude(caps[:powerCapsSize-1]); got != "" {
		t.Fatal("short structure accepted", got)
	}
	want := "$keenPowerCapabilities = @{ sleep_supported=$false; modern_standby=$false; batteries_present=$false }\n"
	if got := powerCapabilitiesPrelude(caps); got != want {
		t.Fatal(got)
	}
	caps[5], caps[20], caps[30] = 1, 7, 1
	want = "$keenPowerCapabilities = @{ sleep_supported=$true; modern_standby=$true; batteries_present=$true }\n"
	if got := powerCapabilitiesPrelude(caps); got != want {
		t.Fatal(got)
	}
}
