package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

type attribute struct {
	Key   string            `json:"key"`
	Value map[string]string `json:"value"`
}

func attr(k, v string) attribute { return attribute{k, map[string]string{"stringValue": v}} }
func otlp(events []Event) []byte {
	records := []any{}
	for _, e := range events {
		attributes := []attribute{attr("keen.event.id", e.ID), attr("keen.source", e.Source), attr("keen.action", e.Action), attr("keen.outcome", e.Outcome), attr("keen.summary", e.Summary), attr("keen.actor", e.Actor), attr("keen.field.agent.version", e.AgentVersion)}
		keys := make([]string, 0, len(e.Fields))
		for k := range e.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := e.Fields[k]
			attributes = append(attributes, attr("keen.field."+k, v))
		}
		records = append(records, map[string]any{"timeUnixNano": fmt.Sprint(e.Timestamp.UnixNano()), "severityNumber": max(1, min(24, e.Severity*2+1)), "body": map[string]string{"stringValue": e.Raw}, "attributes": attributes})
	}
	b, _ := json.Marshal(map[string]any{"resourceLogs": []any{map[string]any{"resource": map[string]any{"attributes": []attribute{attr("service.name", "keen-agent")}}, "scopeLogs": []any{map[string]any{"scope": map[string]string{"name": "keen-agent", "version": "1"}, "logRecords": records}}}}})
	return b
}
func client(c Config) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		b, e := readPrivate(c.CAFile, 1024*1024, false)
		if e != nil {
			return nil, e
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid CA file")
		}
		tlsConfig.RootCAs = roots
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, MaxIdleConns: 2, IdleConnTimeout: 60 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects refused") }}, nil
}

type deliveryError struct {
	status int
	retry  time.Duration
}

func (e deliveryError) Error() string { return fmt.Sprintf("ingestion returned HTTP %d", e.status) }
func send(c Config, sp *Spool, h *http.Client) error {
	events, e := sp.batch()
	if e != nil {
		return e
	}
	if len(events) == 0 {
		return nil
	}
    value, e := credential(c)
    if e != nil { return e }
	payload := otlp(events)
	for len(payload) > 900000 && len(events) > 1 {
		events = events[:len(events)/2]
		payload = otlp(events)
	}
	if len(payload) > 900000 {
		return deliveryError{413, 0}
	}
	req, e := http.NewRequest("POST", c.Endpoint, bytes.NewReader(payload))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+value)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "keen-agent/"+version)
	response, e := h.Do(req)
	if e != nil {
		return errors.New("delivery failed (network/TLS); records retained")
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(body) > 65536 {
		return errors.New("invalid acknowledgement; records retained")
	}
	if response.StatusCode != 200 {
		delay := time.Duration(0)
		if seconds, e := time.ParseDuration(response.Header.Get("Retry-After") + "s"); e == nil {
			delay = min(seconds, time.Hour)
		} else if date, e := http.ParseTime(response.Header.Get("Retry-After")); e == nil {
			delay = min(time.Until(date), time.Hour)
		}
		return deliveryError{response.StatusCode, delay}
	}
	var result struct {
		Partial *struct {
			Rejected json.RawMessage `json:"rejectedLogRecords"`
			Message  string          `json:"errorMessage"`
		} `json:"partialSuccess"`
	}
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) || json.Unmarshal(body, &result) != nil {
		return errors.New("invalid OTLP acknowledgement; records retained")
	}
	if result.Partial != nil && len(result.Partial.Rejected) > 0 && string(result.Partial.Rejected) != "0" && string(result.Partial.Rejected) != `"0"` {
		return errors.New("OTLP partial success: delivery paused; inspect receiver and use replay explicitly")
	}
	ids := map[string]bool{}
	for _, e := range events {
		ids[e.ID] = true
	}
	return sp.ack(ids)
}

func heartbeat(c Config, h *http.Client, health map[string]any) error {
	token, err := credential(c)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(health)
	if err != nil {
		return err
	}
	endpoint := strings.TrimSuffix(c.Endpoint, "/v1/otlp/logs") + "/v1/agents/heartbeat"
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := h.Do(req)
	if err != nil {
		return errors.New("health delivery failed")
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 65536))
	if response.StatusCode != 200 {
		return deliveryError{response.StatusCode, 0}
	}
	return nil
}
