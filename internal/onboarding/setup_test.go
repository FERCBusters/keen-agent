package onboarding

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"keen-agent/internal/agentauth"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEndpoint(t *testing.T) {
	for in, want := range map[string]string{"keen.example": "https://keen.example/api/v1/otlp/logs", "https://keen.example/": "https://keen.example/api/v1/otlp/logs", "https://keen.example:8443": "https://keen.example:8443/api/v1/otlp/logs"} {
		got, e := Endpoint(in)
		if e != nil || got != want {
			t.Fatalf("%q: %q %v", in, got, e)
		}
	}
	for _, bad := range []string{"http://keen.example", "https://user:secret@keen.example", "https://keen.example/api", "https://keen.example?x=1", "https://keen.example?", "https://keen.example#secret", "https://keen.example/%2f", "https://", "https://keen.example\n" + "bad", strings.Repeat("x", 2049)} {
		if _, e := Endpoint(bad); e == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

const testCode = "kc_6f8459a2-2768-41a4-94d5-a0cdcc2d7187.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestRequestLimits(t *testing.T) {
	good := `{"url":"keen.example","code":"` + testCode + `"}`
	r, e := Decode(strings.NewReader(good))
	if e != nil || !strings.HasSuffix(r.URL, "/api/v1/otlp/logs") || r.Code != testCode {
		t.Fatal(e)
	}
	for _, bad := range []string{good + good, good + " trailing", `{"url":"keen.example","code":"short"}`,
		`{"url":"keen.example","token":"` + testCode + `"}`, `{"url":"keen.example","code":"ke_` + testCode[3:] + `"}`,
		`{"url":"keen.example","code":"` + testCode + `","command":"sh"}`, strings.Repeat(" ", 32769)} {
		if _, e := Decode(strings.NewReader(bad)); e == nil {
			t.Error("accepted invalid request", bad)
		}
	}
}

func TestEnrolmentRefusesUntrustedTLSAndRedirects(t *testing.T) {
	requests := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Redirect(w, r, "https://redirect.invalid/", http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	id, _ := agentauth.New(s.URL + "/api/v1/otlp/logs")
	h := client()
	defer h.CloseIdleConnections()
	if _, e := agentauth.Enroll(context.Background(), h, id, testCode, "test"); e == nil || requests != 0 {
		t.Fatal("untrusted TLS accepted")
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	tr := h.Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	}
	wrong := id
	wrong.Endpoint = "https://wrong-host.invalid/api/v1/otlp/logs"
	if _, e := agentauth.Enroll(context.Background(), h, wrong, testCode, "test"); e == nil || requests != 0 {
		t.Fatal("wrong TLS hostname accepted")
	}
	if _, e := agentauth.Enroll(context.Background(), h, id, testCode, "test"); e == nil || requests != 1 {
		t.Fatal("redirect followed", e)
	}
	if tr.Proxy != nil {
		t.Fatal("environment proxy enabled")
	}
}

func TestSetupReplacesAnEarlierConfigurationForTheSameInstance(t *testing.T) {
	write := func(path string, b []byte) error { return os.WriteFile(path, b, 0600) }
	endpoint := "https://keen.example/api/v1/otlp/logs"
	want := []byte(`{"endpoint":"` + endpoint + `","interval_seconds":3600,"state_dir":"/x/state"}`)
	for name, tc := range map[string]struct {
		old   string
		token bool
		code  int
	}{
		"absent":            {"", false, 0},
		"current":           {string(want), false, 0},
		"0.1 json":          {`{"endpoint":"` + endpoint + `","interval_seconds":3600,"state_dir":"/x/state","token_file":"/x/token"}`, true, 0},
		"0.1 yaml":          {"endpoint: \"" + endpoint + "\"\ntoken_file: /etc/keen-workstation/token\nstate_dir: /var/lib/keen-workstation\n", true, 0},
		"another instance":  {`{"endpoint":"https://other.example/api/v1/otlp/logs","token_file":"/x/token"}`, true, Existing},
		"unreadable config": {"{not json", false, Existing},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			if tc.old != "" {
				os.WriteFile(path, []byte(tc.old), 0600)
			}
			if tc.token {
				os.WriteFile(filepath.Join(dir, "token"), []byte("secret"), 0600)
			}
			if code := settleConfig(path, want, endpoint, write); code != tc.code {
				t.Fatal(code)
			}
			got, _ := os.ReadFile(path)
			_, tokenErr := os.Stat(filepath.Join(dir, "token"))
			if tc.code == 0 {
				if string(got) != string(want) || !os.IsNotExist(tokenErr) {
					t.Fatalf("config %q, token %v", got, tokenErr)
				}
				if _, e := os.Stat(path + ".new"); !os.IsNotExist(e) {
					t.Fatal("temporary configuration left behind")
				}
			} else if string(got) != tc.old || (tc.token && tokenErr != nil) {
				t.Fatal("another instance's configuration was changed")
			}
		})
	}
}
