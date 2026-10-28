// Package onboarding owns the fixed, administrator-authorised workstation setup operation.
package onboarding

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"keen-agent/internal/buildinfo"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"keen-agent/internal/agentauth"

	"gopkg.in/yaml.v3"
)

// agentVersion identifies the setup helper in KEEN's request logs.
const agentVersion = buildinfo.Version

type Request struct {
	URL  string `json:"url"`
	Code string `json:"code"`
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
	v.Code = strings.TrimSpace(v.Code)
	if !agentauth.CodePattern.MatchString(v.Code) {
		return v, errors.New("invalid enrolment code")
	}
	var e2 error
	v.URL, e2 = Endpoint(v.URL)
	return v, e2
}
func client() *http.Client {
	return agentauth.Client(&http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: nil})
}

// Setup never accepts commands, service names or destination paths from the
// GUI. It enrols this device's own key with the single-use code, writes a
// configuration that holds no credential, and starts the services.
func Setup(ctx context.Context, r Request) int {
	if !elevated() {
		return Privilege
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
	store := identityStore()
	id, e := store.Load()
	switch {
	case e == nil && id.Enrolled():
		// Retrying after a service error is safe; another instance needs removal first.
		if id.Endpoint != r.URL {
			return Existing
		}
	case e == nil || os.IsNotExist(e):
		if id, e = agentauth.Open(store, r.URL, ""); e != nil {
			return Storage
		}
		if id.Endpoint != r.URL {
			return Existing
		}
		h := client()
		defer h.CloseIdleConnections()
		grant, e := agentauth.Enroll(ctx, h, id, r.Code, "keen-setup/"+agentVersion)
		if e != nil {
			return Connection
		}
		if id.Accept(grant, id.PrivateKey, time.Now()) != nil {
			return Connection
		}
		if store.Save(id) != nil {
			return Storage
		}
	default:
		return Storage
	}
	if code := settleConfig(configPath(), configBytes(r), r.URL, writeNew); code != 0 {
		return code
	}
	if activate(ctx) != nil {
		return Service
	}
	return 0
}

// settleConfig writes the configuration for this KEEN instance. A
// configuration an earlier version wrote for the same instance (KEEN Agent 0.1
// named a token file) is replaced, and its token file removed; one for another
// instance is left alone and reported.
func settleConfig(path string, want []byte, endpoint string, write func(string, []byte) error) int {
	b, e := os.ReadFile(path)
	switch {
	case os.IsNotExist(e):
		if write(path, want) != nil {
			return Storage
		}
		return 0
	case e != nil:
		return Storage
	case bytes.Equal(b, want):
		return 0
	}
	var old struct {
		Endpoint string `yaml:"endpoint"`
	}
	// YAML accepts both the JSON (Windows, macOS) and YAML (Linux) forms.
	if yaml.Unmarshal(b, &old) != nil || old.Endpoint != endpoint {
		return Existing
	}
	next := path + ".new"
	if e := os.Remove(next); e != nil && !os.IsNotExist(e) {
		return Storage
	}
	if write(next, want) != nil {
		return Storage
	}
	if os.Rename(next, path) != nil {
		os.Remove(next)
		return Storage
	}
	if e := os.Remove(filepath.Join(filepath.Dir(path), "token")); e != nil && !os.IsNotExist(e) {
		return Storage
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
