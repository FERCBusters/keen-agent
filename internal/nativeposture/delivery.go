package nativeposture

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"keen-agent/internal/agentauth"
	"keen-agent/internal/posturemodel"
	"keen-agent/internal/ueu"
)

// Config is the companion's protected configuration. The enrolment code is
// needed only until the first enrolment; the setup tools remove it after.
type Config struct {
	Endpoint           string `json:"endpoint"`
	StateDir           string `json:"state_dir"`
	IntervalSeconds    int    `json:"interval_seconds"`
	EnrollmentCodeFile string `json:"enrollment_code_file,omitempty"`
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
	if !filepath.IsAbs(c.StateDir) || (c.EnrollmentCodeFile != "" && !filepath.IsAbs(c.EnrollmentCodeFile)) {
		return c, errors.New("state_dir and enrollment_code_file must be absolute")
	}
	if c.IntervalSeconds == 0 {
		c.IntervalSeconds = 3600
	}
	if c.IntervalSeconds < 300 || c.IntervalSeconds > 86400 {
		return c, errors.New("interval_seconds must be 300..86400")
	}
	if e = privatePath(c.StateDir, true); e != nil {
		return c, e
	}
	return c, nil
}

func client() *http.Client {
	return agentauth.Client(&http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: nil})
}

// Manager opens the identity and its enrolment credential.
func Manager(c Config, h *http.Client) (*agentauth.Manager, error) {
	store := identityStore(c.StateDir)
	id, err := agentauth.Open(store, c.Endpoint, "")
	if err != nil {
		return nil, err
	}
	credential := func() (string, error) {
		if c.EnrollmentCodeFile == "" {
			return "", errors.New("no enrolment code configured")
		}
		if err := privatePath(c.EnrollmentCodeFile, false); err != nil {
			return "", err
		}
		b, err := os.ReadFile(c.EnrollmentCodeFile)
		if err != nil {
			return "", err
		}
		return agentauth.ReadCredential(b)
	}
	return agentauth.NewManager(store, id, h, "keen-posture/"+Version, credential), nil
}

// Enroll binds this device's key using the configured code.
func Enroll(ctx context.Context, c Config) (agentauth.Identity, error) {
	h := client()
	defer h.CloseIdleConnections()
	m, err := Manager(c, h)
	if err != nil {
		return agentauth.Identity{}, err
	}
	if m.Identity().Enrolled() {
		return m.Identity(), nil
	}
	ready, err := m.Ready(ctx, time.Now())
	if !ready && err == nil {
		err = errors.New("enrolment did not complete; retry later")
	}
	return m.Identity(), err
}

func producer(id agentauth.Identity) (ueu.Producer, error) {
	subject, err := id.Subject()
	if err != nil {
		return ueu.Producer{}, err
	}
	asset := id.AssetType
	if asset == "" {
		asset = "workstation"
	}
	return ueu.Producer{Catalogue: ueu.KEEN(), ApplicationID: "keen-posture", ApplicationVersion: Version, InstanceID: id.AgentID, AssetType: asset, Platform: runtime.GOOS, Subject: subject}, nil
}

// Envelopes turns one run into evidence: each measured observation, then the
// run's coverage, so KEEN can tell unmeasured checks from absent ones.
func Envelopes(p ueu.Producer, all []Observation, observedAt time.Time) ([]map[string]any, error) {
	var out []map[string]any
	for _, o := range all {
		if o.Validate() != nil || o.Status != "observed" {
			continue
		}
		kind, value, scope := ueu.LocalAccount(o.Scope)
		env, err := p.Observe(ueu.Observation{Check: o.Check, Provider: o.Provider, Scope: scope, Status: o.Status, Reason: o.Reason, Facts: o.Facts,
			ObservedAt: observedAt, SubjectKind: kind, SubjectValue: value, Method: "native_collector", ValidFor: 24 * time.Hour})
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", o.Check, o.Provider, err)
		}
		out = append(out, env)
	}
	run, err := agentauth.NewSecret()
	if err != nil {
		return nil, err
	}
	c := posturemodel.CoverageOf("native_posture", run[:22], all)
	observed := map[string]bool{}
	for _, v := range c.Observed {
		observed[v] = true
	}
	var unavailable []string
	for _, v := range c.Attempted {
		if !observed[v] {
			unavailable = append(unavailable, v)
		}
	}
	env, err := p.Emit(ueu.Event{Type: "evidence.collection.completed", Component: c.Collector, Action: "collect", Outcome: "info", Time: observedAt,
		Attributes: map[string]string{"collector": c.Collector, "run_id": c.RunID, "checks_attempted": strings.Join(c.Attempted, ","),
			"checks_observed": strings.Join(c.Observed, ","), "checks_unavailable": strings.Join(unavailable, ","), "probes_unavailable": strings.Join(c.Unavailable, ","),
			"checks_attempted_count": fmt.Sprint(len(c.Attempted)), "checks_observed_count": fmt.Sprint(len(c.Observed))}})
	if err != nil {
		return nil, err
	}
	return append(out, env), nil
}

// Preview returns the envelopes a run would produce, sealed with nothing and
// pseudonymised with a throwaway key, for local inspection.
func Preview(all []Observation) ([]map[string]any, error) {
	key, err := ueu.NewPairwiseKey()
	if err != nil {
		return nil, err
	}
	pr := ueu.Producer{Catalogue: ueu.KEEN(), ApplicationID: "keen-posture", ApplicationVersion: Version, InstanceID: "00000000-0000-4000-8000-000000000000", AssetType: "workstation", Platform: runtime.GOOS, Subject: ueu.Subject{Type: "pairwise", Key: key}}
	return Envelopes(pr, all, time.Now().UTC())
}

const maxQueued = 4096

// Deliver seals a run into the local queue, then sends queued evidence. A
// record leaves the queue only after an unambiguous acknowledgement; its
// evidence identifier and bytes stay the same across retries.
func Deliver(ctx context.Context, c Config, all []Observation, observedAt time.Time) error {
	if e := privatePath(c.StateDir, true); e != nil {
		return e
	}
	p := filepath.Join(c.StateDir, "pending.db")
	if _, e := os.Lstat(p); e == nil {
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
	h := client()
	defer h.CloseIdleConnections()
	m, e := Manager(c, h)
	if e != nil {
		return e
	}
	ready, e := m.Ready(ctx, time.Now())
	id := m.Identity()
	if !id.Enrolled() {
		if e == nil {
			e = errors.New("device is not enrolled; run keen-posture -command enroll")
		}
		return e
	}
	pr, err := producer(id)
	if err != nil {
		return err
	}
	envelopes, err := Envelopes(pr, all, observedAt)
	if err != nil {
		return err
	}
	if err = seal(db, id.AgentID, envelopes); err != nil {
		return err
	}
	if !ready {
		if e == nil {
			e = errors.New("credential renewal pending; evidence retained")
		}
		return e
	}
	if err = flushQueue(ctx, db, h, c.Endpoint, id); err != nil {
		var rejected agentauth.HTTPError
		if errors.As(err, &rejected) && (rejected.Status == 401 || rejected.Status == 403) {
			m.Block("agent authentication rejected; administrator intervention required")
		}
		return err
	}
	return heartbeat(ctx, db, h, c.Endpoint, id)
}

func seal(db *bolt.DB, stream string, envelopes []map[string]any) error {
	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("pending"))
		if err != nil {
			return err
		}
		meta, err := tx.CreateBucketIfNotExists([]byte("meta"))
		if err != nil {
			return err
		}
		if b.Stats().KeyN+len(envelopes) > maxQueued {
			return errors.New("posture queue full; older evidence retained")
		}
		var chain ueu.Chain
		if raw := meta.Get([]byte("chain")); raw != nil {
			if err = json.Unmarshal(raw, &chain); err != nil {
				return err
			}
		}
		for _, env := range envelopes {
			sealed, err := ueu.Seal(env, stream, &chain, time.Now())
			if err != nil {
				return err
			}
			v, err := json.Marshal(sealed)
			if err != nil {
				return err
			}
			if err = b.Put([]byte(fmt.Sprintf("%020d", sealed.Sequence)), v); err != nil {
				return err
			}
		}
		raw, err := json.Marshal(chain)
		if err != nil {
			return err
		}
		return meta.Put([]byte("chain"), raw)
	})
}

func pending(db *bolt.DB) ([][]byte, []ueu.Sealed, error) {
	var keys [][]byte
	var batch []ueu.Sealed
	size := 0
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("pending"))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil && len(batch) < 64 && size+len(v) < 700000; k, v = c.Next() {
			var s ueu.Sealed
			if err := json.Unmarshal(v, &s); err != nil {
				return err
			}
			keys, batch = append(keys, bytes.Clone(k)), append(batch, s)
			size += len(v)
		}
		return nil
	})
	return keys, batch, err
}

// checkAck accepts only an unambiguous OTLP success.
func checkAck(b []byte) error {
	if len(bytes.TrimSpace(b)) == 0 {
		return errors.New("empty acknowledgement; evidence retained")
	}
	var ack map[string]json.RawMessage
	if json.Unmarshal(b, &ack) != nil || ack == nil {
		return errors.New("invalid acknowledgement; evidence retained")
	}
	if partial, ok := ack["partialSuccess"]; ok {
		var p map[string]any
		if json.Unmarshal(partial, &p) != nil {
			return errors.New("invalid partial acknowledgement")
		}
		if n, ok := p["rejectedLogRecords"]; ok && n != float64(0) && n != "0" {
			return errors.New("partial rejection; evidence retained")
		}
		if m, ok := p["errorMessage"]; ok && m != "" {
			return errors.New("partial rejection; evidence retained")
		}
	}
	return nil
}

func flushQueue(ctx context.Context, db *bolt.DB, h *http.Client, endpoint string, id agentauth.Identity) error {
	for {
		keys, batch, err := pending(db)
		if err != nil || len(batch) == 0 {
			return err
		}
		payload, err := agentauth.SignedBatch(id, "keen-posture", Version, batch)
		if err != nil {
			return err
		}
		res, err := agentauth.Post(ctx, h, endpoint, ueu.OperationLogs, payload, id, "keen-posture/"+Version)
		if err != nil {
			return err
		}
		if err = checkAck(res.Body); err != nil {
			return err
		}
		if err = db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("pending"))
			for _, k := range keys {
				if err := b.Delete(k); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
}

func heartbeat(ctx context.Context, db *bolt.DB, h *http.Client, endpoint string, id agentauth.Identity) error {
	queued, sequence := 0, int64(0)
	db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket([]byte("pending")); b != nil {
			queued = b.Stats().KeyN
		}
		if m := tx.Bucket([]byte("meta")); m != nil {
			var chain ueu.Chain
			json.Unmarshal(m.Get([]byte("chain")), &chain)
			sequence = chain.Sequence
		}
		return nil
	})
	body, _ := json.Marshal(map[string]any{"version": Version, "queued": queued, "chain_sequence": sequence, "updated_at": time.Now().UTC()})
	_, err := agentauth.Post(ctx, h, agentauth.Base(endpoint)+"/v1/agents/heartbeat", ueu.OperationHeartbeat, body, id, "keen-posture/"+Version)
	return err
}
