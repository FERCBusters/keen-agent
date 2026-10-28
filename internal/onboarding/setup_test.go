package onboarding

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"keen-agent/internal/agentauth"
	"net"
	"net/http"
	"net/http/httptest"
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
