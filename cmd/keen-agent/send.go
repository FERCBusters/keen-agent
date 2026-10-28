package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"keen-agent/internal/agentauth"
	"keen-agent/internal/ueu"
)

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
	return agentauth.Client(&http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, MaxIdleConns: 2, IdleConnTimeout: 60 * time.Second}), nil
}

type deliveryError struct {
	status int
	retry  time.Duration
}

func (e deliveryError) Error() string { return fmt.Sprintf("ingestion returned HTTP %d", e.status) }

func asDelivery(err error) error {
	var rejected agentauth.HTTPError
	if errors.As(err, &rejected) {
		return deliveryError{rejected.Status, rejected.Retry}
	}
	return err
}

// signedBatch encodes records with a manifest signed by the current key.
func signedBatch(id agentauth.Identity, records []record) ([]byte, error) {
	sealed := make([]ueu.Sealed, len(records))
	for i, r := range records {
		sealed[i] = r.sealed()
	}
	return agentauth.SignedBatch(id, "keen-agent", version, sealed)
}

func send(c Config, sp *Spool, h *http.Client, id agentauth.Identity) error {
	records, e := sp.batch()
	if e != nil || len(records) == 0 {
		return e
	}
	payload, e := signedBatch(id, records)
	for e == nil && len(payload) > 900000 && len(records) > 1 {
		records = records[:len(records)/2]
		payload, e = signedBatch(id, records)
	}
	if e != nil {
		return e
	}
	if len(payload) > 900000 {
		return deliveryError{413, 0}
	}
	res, e := agentauth.Post(context.Background(), h, c.Endpoint, ueu.OperationLogs, payload, id, "keen-agent/"+version)
	if e != nil {
		if strings.HasPrefix(e.Error(), "request failed") {
			return errors.New("delivery failed (network/TLS); records retained")
		}
		return asDelivery(e)
	}
	var result struct {
		Partial *struct {
			Rejected json.RawMessage `json:"rejectedLogRecords"`
			Message  string          `json:"errorMessage"`
		} `json:"partialSuccess"`
	}
	if !bytes.HasPrefix(bytes.TrimSpace(res.Body), []byte("{")) || json.Unmarshal(res.Body, &result) != nil {
		return errors.New("invalid OTLP acknowledgement; records retained")
	}
	if result.Partial != nil && len(result.Partial.Rejected) > 0 && string(result.Partial.Rejected) != "0" && string(result.Partial.Rejected) != `"0"` {
		return errors.New("OTLP partial success: delivery paused; inspect receiver and use replay explicitly")
	}
	ids := map[string]bool{}
	for _, r := range records {
		ids[r.EvidenceID] = true
	}
	return sp.ack(ids)
}

func heartbeat(c Config, h *http.Client, id agentauth.Identity, health map[string]any) error {
	payload, err := json.Marshal(health)
	if err != nil {
		return err
	}
	_, err = agentauth.Post(context.Background(), h, agentauth.Base(c.Endpoint)+"/v1/agents/heartbeat", ueu.OperationHeartbeat, payload, id, "keen-agent/"+version)
	if err != nil {
		if strings.HasPrefix(err.Error(), "request failed") {
			return errors.New("health delivery failed")
		}
		return asDelivery(err)
	}
	return nil
}
