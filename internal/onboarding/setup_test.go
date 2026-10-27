package onboarding

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
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
func TestRequestLimits(t *testing.T) {
	good := `{"url":"keen.example","token":"0123456789abcdef"}`
	r, e := Decode(strings.NewReader(good))
	if e != nil || !strings.HasSuffix(r.URL, "/api/v1/otlp/logs") {
		t.Fatal(e)
	}
	for _, bad := range []string{good + good, good + " trailing", `{"url":"keen.example","token":"short"}`, `{"url":"keen.example","token":"0123456789 abcdef"}`, `{"url":"keen.example","token":"0123456789abcdef","command":"sh"}`, strings.Repeat(" ", 32769)} {
		if _, e := Decode(strings.NewReader(bad)); e == nil {
			t.Error("accepted invalid request")
		}
	}
}
func TestConnectionAcknowledgements(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		ok     bool
	}{{200, `{"ok":true}`, true}, {200, `{}`, false}, {401, `{"ok":true}`, false}, {200, strings.Repeat("x", 4097), false}, {200, `null`, false}, {302, `{"ok":true}`, false}} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/agents/heartbeat" || r.Header.Get("Authorization") != "Bearer 0123456789abcdef" {
				t.Error("incorrect credential endpoint")
			}
			w.Header().Set("Location", "https://redirect.invalid")
			w.WriteHeader(tc.status)
			io.WriteString(w, tc.body)
		}))
		h := server.Client()
		h.CheckRedirect = client().CheckRedirect
		e := verify(context.Background(), h, Request{server.URL + "/api/v1/otlp/logs", "0123456789abcdef"})
		if (e == nil) != tc.ok {
			t.Errorf("status %d: %v", tc.status, e)
		}
		server.Close()
	}
}
func TestTLSRejectsBeforeSendingToken(t *testing.T) {
	requests := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer s.Close()
	r := Request{s.URL + "/api/v1/otlp/logs", "0123456789abcdef"}
	h := client()
	defer h.CloseIdleConnections()
	if verify(context.Background(), h, r) == nil || requests != 0 {
		t.Fatal("untrusted TLS accepted")
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	tr := h.Transport.(*http.Transport)
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	}
	r.URL = "https://wrong-host.invalid/api/v1/otlp/logs"
	if verify(context.Background(), h, r) == nil || requests != 0 {
		t.Fatal("wrong TLS hostname accepted")
	}
	r.URL = s.URL + "/api/v1/otlp/logs"
	if e := verify(context.Background(), h, r); e != nil || requests != 1 {
		t.Fatal("valid trusted TLS refused", e)
	}
	if tr.Proxy != nil {
		t.Fatal("environment proxy enabled")
	}
}
