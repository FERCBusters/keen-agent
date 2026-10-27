// Package onboarding owns the fixed, administrator-authorised workstation setup operation.
package onboarding

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Request struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// Exit codes are public UI messages. Never return request values or upstream bodies.
const (
	Invalid    = 10
	Connection = 11
	Existing   = 12
	Storage    = 13
	Service    = 14
	Privilege  = 15
)

func Endpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("enter an HTTPS instance domain without a path, query or credentials")
	}
	u.Path = "/api/v1/otlp/logs"
	return u.String(), nil
}
func Decode(r io.Reader) (Request, error) {
	var v Request
	b, e := io.ReadAll(io.LimitReader(r, 32769))
	if e != nil || len(b) > 32768 {
		return v, errors.New("invalid request")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil {
		return v, errors.New("invalid request")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return v, errors.New("invalid request")
	}
	v.Token = strings.TrimSpace(v.Token)
	if len(v.Token) < 16 || len(v.Token) > 16384 || strings.ContainsAny(v.Token, " \r\n\t") {
		return v, errors.New("invalid token")
	}
	for _, c := range v.Token {
		if c < 33 || c > 126 {
			return v, errors.New("invalid token")
		}
	}
	var e2 error
	v.URL, e2 = Endpoint(v.URL)
	return v, e2
}
func client() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}
func verify(ctx context.Context, h *http.Client, r Request) error {
	// A heartbeat verifies the individual credential without creating artificial evidence.
	target := strings.TrimSuffix(r.URL, "/v1/otlp/logs") + "/v1/agents/heartbeat"
	req, e := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(`{"version":"0.1.10"}`))
	if e != nil {
		return errors.New("connection failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.Token)
	res, e := h.Do(req)
	if e != nil {
		return errors.New("connection failed")
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 4097))
	if e != nil || len(b) > 4096 || res.StatusCode != 200 {
		return errors.New("connection rejected")
	}
	var ack struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(b, &ack) != nil || !ack.OK {
		return errors.New("connection rejected")
	}
	return nil
}

// Setup never accepts commands, service names or destination paths from the GUI.
func Setup(ctx context.Context, r Request) int {
	if !elevated() {
		return Privilege
	}
	h := client()
	defer h.CloseIdleConnections()
	if verify(ctx, h, r) != nil {
		return Connection
	}
	if e := prepare(); e != nil {
		return Storage
	}
	root := configRoot()
	// An exclusive create provides a cross-process lock in the protected directory.
	lock, e := os.OpenFile(filepath.Join(root, "setup.lock"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return Storage
	}
	lock.Close()
	defer os.Remove(filepath.Join(root, "setup.lock"))
	tokenPath := filepath.Join(root, "token")
	if b, e := os.ReadFile(tokenPath); e == nil {
		// Retrying the same connection after a service error is safe; rotation is explicit.
		if string(b) != r.Token {
			return Existing
		}
		b, e = os.ReadFile(configPath())
		if e != nil || !bytes.Equal(b, configBytes(r)) {
			return Existing
		}
	} else if !os.IsNotExist(e) {
		return Storage
	} else {
		if _, e = os.Lstat(configPath()); !os.IsNotExist(e) {
			return Existing
		}
		if writeNew(tokenPath, []byte(r.Token)) != nil {
			return Storage
		}
		if writeNew(configPath(), configBytes(r)) != nil {
			os.Remove(tokenPath)
			return Storage
		}
	}
	if activate(ctx) != nil {
		return Service
	}
	return 0
}
func writeNew(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if e = protectFile(path); e != nil {
		return e
	}
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	ok = true
	return nil
}
