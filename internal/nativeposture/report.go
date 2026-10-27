// Package nativeposture is the portable companion for macOS and Windows.
package nativeposture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	model "keen-agent/internal/posturemodel"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const Version = "0.1.9"

type Observation = model.Observation
type Report struct {
	Schema       int           `json:"schema_version"`
	Version      string        `json:"agent_version"`
	Platform     string        `json:"platform"`
	ObservedAt   time.Time     `json:"observed_at"`
	Observations []Observation `json:"observations"`
	Diagnostics  []Observation `json:"diagnostics,omitempty"`
}
type Runner interface {
	Run(context.Context, string, []string, []byte) ([]byte, error)
}
type LocalRunner struct{}
type bounded struct{ bytes.Buffer }

func (b *bounded) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1024*1024 {
		return 0, errors.New("query output exceeds limit")
	}
	return b.Buffer.Write(p)
}
func (LocalRunner) Run(ctx context.Context, path string, args []string, input []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resolved, err := trustedExecutable(path)
	if err != nil {
		return nil, err
	}
	c := exec.CommandContext(ctx, resolved, args...)
	c.Args[0] = path
	prepareCommand(c)
	c.Stdin = bytes.NewReader(input)
	var out bounded
	c.Stdout = &out
	c.Stderr = io.Discard
	c.WaitDelay = time.Second
	if err := c.Run(); err != nil {
		return nil, errors.New("native query failed")
	}
	return out.Bytes(), nil
}
func NewReport(all []Observation, diagnostics bool) Report {
	r := Report{1, Version, runtime.GOOS, time.Now().UTC(), []Observation{}, nil}
	for _, o := range all {
		if err := o.Validate(); err != nil {
			continue
		}
		if o.Status == "observed" {
			r.Observations = append(r.Observations, o)
		} else if diagnostics {
			r.Diagnostics = append(r.Diagnostics, o)
		}
	}
	return r
}
func DecodeObservations(b []byte) ([]Observation, error) {
	if len(b) > 1024*1024 {
		return nil, errors.New("report too large")
	}
	b = bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf})
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var all []Observation
	if err := dec.Decode(&all); err != nil {
		return nil, err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	if len(all) > 256 {
		return nil, errors.New("too many observations")
	}
	for _, o := range all {
		if err := o.Validate(); err != nil {
			return nil, err
		}
	}
	return all, nil
}
func observed(check, provider, scope, reason string, f map[string]string) Observation {
	o := model.New(check, provider, scope)
	o.Status = "observed"
	o.Reason = reason
	o.Facts = f
	return o
}
func unavailable(check, provider string) Observation {
	o := model.New(check, provider, "host")
	o.Reason = "query_unavailable"
	return o
}
func query(ctx context.Context, r Runner, path string, args ...string) (string, error) {
	b, e := r.Run(ctx, path, args, nil)
	return strings.TrimSpace(string(b)), e
}
