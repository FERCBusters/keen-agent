package nativeposture

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Endpoint        string `json:"endpoint"`
	TokenFile       string `json:"token_file"`
	StateDir        string `json:"state_dir"`
	IntervalSeconds int    `json:"interval_seconds"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	if !filepath.IsAbs(path) {
		return c, errors.New("configuration path must be absolute")
	}
	if err := privatePath(path, false); err != nil {
		return c, err
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	if len(b) > 16384 {
		return c, errors.New("configuration too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("trailing configuration")
	}
	u, e := url.Parse(c.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(u.Path, "/v1/otlp/logs") {
		return c, errors.New("endpoint must be HTTPS ending in /v1/otlp/logs, without credentials or query")
	}
	if !filepath.IsAbs(c.TokenFile) || !filepath.IsAbs(c.StateDir) {
		return c, errors.New("token_file and state_dir must be absolute")
	}
	if c.IntervalSeconds == 0 {
		c.IntervalSeconds = 3600
	}
	if c.IntervalSeconds < 300 || c.IntervalSeconds > 86400 {
		return c, errors.New("interval_seconds must be 300..86400")
	}
	if e = privatePath(c.TokenFile, false); e != nil {
		return c, e
	}
	if e = privatePath(c.StateDir, true); e != nil {
		return c, e
	}
	return c, nil
}
func attr(k, v string) any {
	return map[string]any{"key": k, "value": map[string]string{"stringValue": v}}
}
func Payload(r Report) ([]byte, error) {
	records := []any{}
	for _, o := range r.Observations {
		if e := o.Validate(); e != nil {
			return nil, e
		}
		if o.Status != "observed" {
			continue
		}
		id := make([]byte, 16)
		if _, e := rand.Read(id); e != nil {
			return nil, e
		}
		id[6] = (id[6] & 15) | 64
		id[8] = (id[8] & 63) | 128
		s := hex.EncodeToString(id)
		uuid := s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
		a := []any{attr("keen.event.id", uuid), attr("keen.source", "posture"), attr("keen.action", "posture."+o.Check), attr("keen.outcome", "info"), attr("keen.summary", o.Check+" ("+o.Provider+"): "+o.Reason), attr("keen.actor", ""), attr("keen.field.agent.version", Version), attr("keen.field.posture.schema_version", "1"), attr("keen.field.posture.check", o.Check), attr("keen.field.posture.provider", o.Provider), attr("keen.field.posture.scope", o.Scope), attr("keen.field.posture.status", o.Status), attr("keen.field.posture.reason", o.Reason), attr("keen.field.posture.authority", "native_collector"), attr("keen.field.posture.platform", r.Platform), attr("keen.field.posture.observed_at", r.ObservedAt.Format(time.RFC3339Nano))}
		keys := []string{}
		for k := range o.Facts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			a = append(a, attr("keen.field.posture."+k, o.Facts[k]))
		}
		raw, e := json.Marshal(o)
		if e != nil {
			return nil, e
		}
		records = append(records, map[string]any{"attributes": a, "timeUnixNano": strconv.FormatInt(r.ObservedAt.UnixNano(), 10), "severityNumber": 7, "body": map[string]string{"stringValue": string(raw)}})
	}
	return json.Marshal(map[string]any{"resourceLogs": []any{map[string]any{"resource": map[string]any{"attributes": []any{attr("service.name", "keen-agent")}}, "scopeLogs": []any{map[string]any{"scope": map[string]string{"name": "keen-posture", "version": Version}, "logRecords": records}}}}})
}

// Deliver queues first and only deletes a report after an unambiguous acknowledgement.
// A report retains its event IDs across retries. Local Bolt locking prevents overlaps.
func Deliver(ctx context.Context, c Config, r Report) error {
	if e := privatePath(c.StateDir, true); e != nil {
		return e
	}
	if e := privatePath(c.TokenFile, false); e != nil {
		return e
	}
	token, e := os.ReadFile(c.TokenFile)
	if e != nil {
		return e
	}
	t := strings.TrimSpace(string(token))
	if len(t) < 16 || len(t) > 16384 || strings.ContainsAny(t, "\r\n\t ") {
		return errors.New("invalid token file")
	}
	p := filepath.Join(c.StateDir, "pending.db")
	if _, e = os.Lstat(p); e == nil {
		if e = privatePath(p, false); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	db, e := bolt.Open(p, 0600, &bolt.Options{Timeout: time.Second})
	if e != nil {
		return errors.New("cannot lock posture queue")
	}
	defer db.Close()
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	defer client.CloseIdleConnections()
	// Drain old reports before adding new ones so a previously full queue can recover.
	flush := func() error { return flushQueue(ctx, db, client, c.Endpoint, t) }
	oldErr := flush()
	if len(r.Observations) > 0 {
		payload, e := Payload(r)
		if e != nil {
			return e
		}
		if len(payload) > 900000 {
			return errors.New("report exceeds ingestion limit")
		}
		if e = db.Update(func(tx *bolt.Tx) error {
			b, e := tx.CreateBucketIfNotExists([]byte("pending"))
			if e != nil {
				return e
			}
			if b.Stats().KeyN >= 128 {
				return errors.New("posture queue full; old reports retained")
			}
			seq, e := b.NextSequence()
			if e != nil {
				return e
			}
			return b.Put([]byte(fmt.Sprintf("%020d", seq)), payload)
		}); e != nil {
			return e
		}
	}
	if oldErr != nil {
		return oldErr
	}
	return flush()
}
func post(ctx context.Context, h *http.Client, endpoint, token string, payload []byte) error {
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "keen-posture/"+Version)
	resp, e := h.Do(req)
	if e != nil {
		return errors.New("network/TLS failure; report retained")
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(b) > 65536 {
		return errors.New("invalid acknowledgement; report retained")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d; report retained", resp.StatusCode)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return errors.New("empty acknowledgement; report retained")
	}
	var ack map[string]json.RawMessage
	if json.Unmarshal(b, &ack) != nil || ack == nil {
		return errors.New("invalid acknowledgement; report retained")
	}
	if partial, ok := ack["partialSuccess"]; ok {
		var p map[string]any
		if json.Unmarshal(partial, &p) != nil {
			return errors.New("invalid partial acknowledgement")
		}
		if n, ok := p["rejectedLogRecords"]; ok && n != float64(0) && n != "0" {
			return errors.New("partial rejection; report retained")
		}
		if m, ok := p["errorMessage"]; ok && m != "" {
			return errors.New("partial rejection; report retained")
		}
	}
	return nil
}

func flushQueue(ctx context.Context, db *bolt.DB, h *http.Client, endpoint, token string) error {
	for {
		var key, payload []byte
		err := db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("pending"))
			if b == nil {
				return nil
			}
			k, v := b.Cursor().First()
			key = bytes.Clone(k)
			payload = bytes.Clone(v)
			return nil
		})
		if err != nil {
			return err
		}
		if key == nil {
			return nil
		}
		if err = post(ctx, h, endpoint, token, payload); err != nil {
			return err
		}
		if err = db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("pending")).Delete(key) }); err != nil {
			return err
		}
	}
}
