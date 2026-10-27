package nativeposture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	bolt "go.etcd.io/bbolt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
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
func TestQuietReportAndPayload(t *testing.T) {
	r := NewReport([]Observation{unavailable("antivirus", "missing"), observed("firewall", "windows_firewall", "Public", "state_observed", map[string]string{"enabled": "false"})}, true)
	if len(r.Observations) != 1 || len(r.Diagnostics) != 1 {
		t.Fatal(r)
	}
	b, e := Payload(r)
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, v := range []string{"keen.event.id", "posture.firewall", "native_collector", "false"} {
		if !strings.Contains(s, v) {
			t.Fatal(s)
		}
	}
	if strings.Contains(s, "missing") {
		t.Fatal("diagnostics leaked")
	}
}
func TestAcknowledgement(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
		ok     bool
	}{{`{}`, 200, true}, {`{"partialSuccess":{"rejectedLogRecords":"0"}}`, 200, true}, {`{"partialSuccess":{"rejectedLogRecords":"1"}}`, 200, false}, {`null`, 200, false}, {``, 200, false}, {`not json`, 200, false}, {`{}`, 401, false}, {`{"partialSuccess":{"errorMessage":"error"}}`, 200, false}} {
		t.Run(tc.body+string(rune(tc.status)), func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("token missing")
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer s.Close()
			e := post(context.Background(), s.Client(), s.URL, "test-token", []byte(`{}`))
			if (e == nil) != tc.ok {
				t.Fatalf("%v", e)
			}
		})
	}
}

func TestQueuePartialAckAndRetry(t *testing.T) {
	db, e := bolt.Open(filepath.Join(t.TempDir(), "queue.db"), 0600, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	first := []byte(`{"report":1}`)
	second := []byte(`{"report":2}`)
	if e = db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucket([]byte("pending"))
		if e != nil {
			return e
		}
		if e = b.Put([]byte("1"), first); e != nil {
			return e
		}
		return b.Put([]byte("2"), second)
	}); e != nil {
		t.Fatal(e)
	}
	fail := true
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, string(b))
		if fail && string(b) == string(second) {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	if e = flushQueue(context.Background(), db, server.Client(), server.URL, "test-token"); e == nil {
		t.Fatal("expected failure")
	}
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("pending"))
		if b.Get([]byte("1")) != nil || !bytes.Equal(b.Get([]byte("2")), second) {
			t.Fatal("acknowledged batch not committed or failed batch lost")
		}
		return nil
	})
	fail = false
	if e = flushQueue(context.Background(), db, server.Client(), server.URL, "test-token"); e != nil {
		t.Fatal(e)
	}
	if len(seen) != 3 || seen[1] != seen[2] {
		t.Fatal("retry changed payload", seen)
	}
	db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("pending")).Stats().KeyN != 0 {
			t.Fatal("queue not drained")
		}
		return nil
	})
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
