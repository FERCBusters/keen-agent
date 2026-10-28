package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	bolt "go.etcd.io/bbolt"
	"keen-agent/internal/posturemodel"
	"keen-agent/internal/ueu"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

var full = errors.New("queue full: collection paused until delivery frees space")
var q = []byte("queue")
var cp = []byte("checkpoints")
var meta = []byte("meta")

// Event is a parsed record before it becomes evidence. Fields drive
// structured filters and classification; they are not sent as such.
type Event struct {
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
	Actor     string            `json:"actor,omitempty"`
	Action    string            `json:"action"`
	Outcome   string            `json:"outcome"`
	Severity  int               `json:"severity"`
	Summary   string            `json:"summary"`
	Raw       string            `json:"raw"`
	Fields    map[string]string `json:"fields"`
	// Ref locates the source record on this host (journal cursor or file offset).
	Ref string `json:"ref,omitempty"`
	// Posture observations and run coverage arrive through the posture parser.
	Posture   *posturemodel.Observation `json:"posture,omitempty"`
	Coverage  *posturemodel.Coverage    `json:"coverage,omitempty"`
	Authority string                    `json:"authority,omitempty"`
}

// record is a sealed envelope waiting for delivery.
type record struct {
	EvidenceID string    `json:"evidence_id"`
	EventType  string    `json:"event_type"`
	EventTime  time.Time `json:"event_time"`
	Outcome    string    `json:"outcome"`
	Canonical  string    `json:"canonical"`
	Hash       string    `json:"hash"`
	Sequence   int64     `json:"sequence"`
}

func (r record) sealed() ueu.Sealed {
	return ueu.Sealed{EvidenceID: r.EvidenceID, EventType: r.EventType, EventTime: r.EventTime, Outcome: r.Outcome, Canonical: []byte(r.Canonical), Hash: r.Hash, Sequence: r.Sequence}
}

type queued struct {
	Record record    `json:"record"`
	Added  time.Time `json:"added"`
}

// Spool is the durable queue. Envelopes are sealed in the transaction that
// queues them, so the sequence and hash chain never skip or repeat.
type Spool struct {
	db     *bolt.DB
	limit  int64
	sealer *sealer
}

func openSpool(dir string, limit int64) (*Spool, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state directory must be a real private directory (0700)")
	}
	path := filepath.Join(dir, "spool.db")
	if st, e := os.Lstat(path); e == nil && (!st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0) {
		return nil, errors.New("spool must be regular and private")
	}
	db, e := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if e != nil {
		return nil, e
	}
	s := &Spool{db: db, limit: limit}
	e = db.Update(func(t *bolt.Tx) error {
		for _, b := range [][]byte{q, cp, meta} {
			if _, e := t.CreateBucketIfNotExists(b); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func integer(b []byte) int64 {
	if len(b) != 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b))
}
func putInt(b *bolt.Bucket, key string, n int64) error {
	v := make([]byte, 8)
	binary.BigEndian.PutUint64(v, uint64(n))
	return b.Put([]byte(key), v)
}
func (s *Spool) checkpoint(key string, v any) error {
	return s.db.View(func(t *bolt.Tx) error {
		b := t.Bucket(cp).Get([]byte(key))
		if b == nil {
			return nil
		}
		return json.Unmarshal(b, v)
	})
}
func (s *Spool) add(envelopes []map[string]any, key string, state any, filtered ...filterTally) error {
	if len(envelopes) > 0 && s.sealer == nil {
		return errors.New("agent is not enrolled; evidence cannot be sealed")
	}
	return s.db.Update(func(t *bolt.Tx) error {
		m := t.Bucket(meta)
		for _, tally := range filtered {
			if tally.count > 0 {
				key := tally.kind + ":" + tally.source
				if err := putInt(m, key, integer(m.Get([]byte(key)))+tally.count); err != nil {
					return err
				}
			}
		}
		size := integer(m.Get([]byte("bytes")))
		count := integer(m.Get([]byte("count")))
		if err := s.seal(t, envelopes, &size, &count); err != nil {
			return err
		}
		if key != "" {
			b, e := json.Marshal(state)
			if e != nil {
				return e
			}
			if t.Bucket(cp).Get([]byte(key)) == nil && t.Bucket(cp).Stats().KeyN >= 4096 {
				return errors.New("checkpoint limit reached; review rotated file retention")
			}
			old := t.Bucket(cp).Get([]byte(key))
			checkpointBytes := integer(m.Get([]byte("checkpoint_bytes"))) + int64(len(b)-len(old))
			if checkpointBytes > min(s.limit/4, 16*1024*1024) || size+checkpointBytes > s.limit {
				return full
			}
			if e = putInt(m, "checkpoint_bytes", checkpointBytes); e != nil {
				return e
			}
			if e = t.Bucket(cp).Put([]byte(key), b); e != nil {
				return e
			}
		}
		if size+integer(m.Get([]byte("checkpoint_bytes"))) > s.limit {
			return full
		}
		if e := putInt(m, "bytes", size); e != nil {
			return e
		}
		return putInt(m, "count", count)
	})
}

// chainPosition reports the last sealed sequence for health reports.
// seal chains envelopes and appends them to the queue within transaction t,
// adding their bytes and count to size and count.
func (s *Spool) seal(t *bolt.Tx, envelopes []map[string]any, size, count *int64) error {
	if len(envelopes) == 0 {
		return nil
	}
	m, queue := t.Bucket(meta), t.Bucket(q)
	var chain ueu.Chain
	if b := m.Get([]byte("ueu_chain")); b != nil {
		if err := json.Unmarshal(b, &chain); err != nil {
			return err
		}
	}
	for _, env := range envelopes {
		sealed, err := ueu.Seal(env, s.sealer.producer.InstanceID, &chain, time.Now())
		if err != nil {
			return err
		}
		r := record{sealed.EvidenceID, sealed.EventType, sealed.EventTime, sealed.Outcome, string(sealed.Canonical), sealed.Hash, sealed.Sequence}
		b, err := json.Marshal(queued{r, time.Now().UTC()})
		if err != nil {
			return err
		}
		*size += int64(len(b))
		if *size > s.limit {
			return full
		}
		seq, err := queue.NextSequence()
		if err != nil {
			return err
		}
		k := make([]byte, 8)
		binary.BigEndian.PutUint64(k, seq)
		if err = queue.Put(k, b); err != nil {
			return err
		}
		*count++
	}
	b, err := json.Marshal(chain)
	if err != nil {
		return err
	}
	return m.Put([]byte("ueu_chain"), b)
}

// legacyQueued is a record queued by KEEN Agent 0.1 as a plain event.
type legacyQueued struct {
	Event *Event `json:"event"`
}

// upgradeQueue seals the records an earlier agent version queued as plain
// events, in their original order, so an upgrade neither loses them nor sends
// them unsigned. It runs once the agent is enrolled and before collection.
// A record the catalogue cannot express is counted as rejected, as new
// records are.
func (s *Spool) upgradeQueue(sources []Source) (int64, error) {
	if s.sealer == nil {
		return 0, nil
	}
	byName := map[string]Source{}
	for _, source := range sources {
		byName[source.Name] = source
	}
	var sealed int64
	err := s.db.Update(func(t *bolt.Tx) error {
		m := t.Bucket(meta)
		size := integer(m.Get([]byte("bytes")))
		count := integer(m.Get([]byte("count")))
		rejected := integer(m.Get([]byte("rejected")))
		var envelopes []map[string]any
		var keys [][]byte
		queue := t.Bucket(q)
		c := queue.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var old legacyQueued
			if json.Unmarshal(v, &old) != nil || old.Event == nil {
				continue
			}
			source, ok := byName[old.Event.Source]
			if !ok {
				// The source has since been removed: the default evidence mode applies.
				source = Source{Name: old.Event.Source}
			}
			out, err := s.sealer.envelopes(source, *old.Event)
			if err != nil {
				rejected++
			}
			envelopes = append(envelopes, out...)
			size -= int64(len(v))
			count--
			keys = append(keys, append([]byte(nil), k...))
		}
		if len(keys) == 0 {
			return nil
		}
		for _, k := range keys {
			if err := queue.Delete(k); err != nil {
				return err
			}
		}
		if err := s.seal(t, envelopes, &size, &count); err != nil {
			return err
		}
		sealed = int64(len(envelopes))
		if err := putInt(m, "rejected", rejected); err != nil {
			return err
		}
		if err := putInt(m, "bytes", size); err != nil {
			return err
		}
		return putInt(m, "count", count)
	})
	return sealed, err
}

func (s *Spool) chainPosition() int64 {
	var chain ueu.Chain
	s.db.View(func(t *bolt.Tx) error {
		if b := t.Bucket(meta).Get([]byte("ueu_chain")); b != nil {
			json.Unmarshal(b, &chain)
		}
		return nil
	})
	return chain.Sequence
}

func (s *Spool) batch() ([]record, error) {
	out := []record{}
	size := 0
	e := s.db.View(func(t *bolt.Tx) error {
		c := t.Bucket(q).Cursor()
		for k, v := c.First(); k != nil && len(out) < 64; k, v = c.Next() {
			var r queued
			if e := json.Unmarshal(v, &r); e != nil {
				return e
			}
			if size+len(v) > 700000 {
				break
			}
			out = append(out, r.Record)
			size += len(v)
		}
		return nil
	})
	return out, e
}
func (s *Spool) ack(ids map[string]bool) error {
	return s.db.Update(func(t *bolt.Tx) error {
		m := t.Bucket(meta)
		size := integer(m.Get([]byte("bytes")))
		count := integer(m.Get([]byte("count")))
		bucket := t.Bucket(q)
		c := bucket.Cursor()
		remaining := make(map[string]bool, len(ids))
		for id, accepted := range ids {
			if accepted {
				remaining[id] = true
			}
		}
		var keys [][]byte
		for k, v := c.First(); k != nil && len(remaining) > 0; k, v = c.Next() {
			var r queued
			if e := json.Unmarshal(v, &r); e != nil {
				return e
			}
			if remaining[r.Record.EvidenceID] {
				keys = append(keys, append([]byte(nil), k...))
				size -= int64(len(v))
				count--
				delete(remaining, r.Record.EvidenceID)
			}
		}
		for _, key := range keys {
			if e := bucket.Delete(key); e != nil {
				return e
			}
		}

		if e := putInt(m, "bytes", size); e != nil {
			return e
		}
		return putInt(m, "count", count)
	})
}
func (s *Spool) stats() (int64, int64, int64) {
	var count, size, dropped int64
	s.db.View(func(t *bolt.Tx) error {
		m := t.Bucket(meta)
		count = integer(m.Get([]byte("count")))
		size = integer(m.Get([]byte("bytes"))) + integer(m.Get([]byte("checkpoint_bytes")))
		dropped = integer(m.Get([]byte("rejected")))
		return nil
	})
	return count, size, dropped
}
func (s *Spool) reject() error {
	return s.db.Update(func(t *bolt.Tx) error {
		m := t.Bucket(meta)
		return putInt(m, "rejected", integer(m.Get([]byte("rejected")))+1)
	})
}

// discard describes queued evidence removed before delivery.
type discard struct {
	reason      string
	count       int64
	first, last int64
}

func (d *discard) note(r record) {
	d.count++
	if d.first == 0 || r.Sequence < d.first {
		d.first = r.Sequence
	}
	if r.Sequence > d.last {
		d.last = r.Sequence
	}
}

func (s *Spool) expire(days int) (discard, error) {
	d := discard{reason: "queue_retention"}
	if days == 0 {
		return d, nil
	}
	err := s.db.Update(func(t *bolt.Tx) error {
		m := t.Bucket(meta)
		size := integer(m.Get([]byte("bytes")))
		count := integer(m.Get([]byte("count")))
		dropped := integer(m.Get([]byte("rejected")))
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		c := t.Bucket(q).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var r queued
			if e := json.Unmarshal(v, &r); e != nil {
				return e
			}
			if r.Added.Before(cutoff) {
				size -= int64(len(v))
				count--
				dropped++
				d.note(r.Record)
				if e := c.Delete(); e != nil {
					return e
				}
			}
		}
		if e := putInt(m, "bytes", size); e != nil {
			return e
		}
		if e := putInt(m, "count", count); e != nil {
			return e
		}
		return putInt(m, "rejected", dropped)
	})
	return d, err
}

// purgeQueue deliberately discards pending delivery without resetting read positions.
func (s *Spool) purgeQueue() (discard, error) {
	d := discard{reason: "operator_purge"}
	err := s.db.Update(func(t *bolt.Tx) error {
		m := t.Bucket(meta)
		c := t.Bucket(q).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var r queued
			if json.Unmarshal(v, &r) == nil {
				d.note(r.Record)
			}
		}
		if err := t.DeleteBucket(q); err != nil {
			return err
		}
		if _, err := t.CreateBucket(q); err != nil {
			return err
		}
		if err := putInt(m, "count", 0); err != nil {
			return err
		}
		if err := putInt(m, "bytes", 0); err != nil {
			return err
		}
		return putInt(m, "rejected", integer(m.Get([]byte("rejected")))+d.count)
	})
	return d, err
}

// recordDiscard queues a signed statement of what was discarded, so KEEN can
// explain the resulting gap in the sequence.
func (s *Spool) recordDiscard(d discard) error {
	if d.count == 0 || s.sealer == nil {
		return nil
	}
	env, err := s.sealer.producer.Emit(ueu.Event{
		Type: "evidence.records.discarded", Component: "queue", Action: "discard", Outcome: "info", Time: time.Now(),
		Attributes: map[string]string{"reason": d.reason, "count": strconv.FormatInt(d.count, 10), "first_sequence": strconv.FormatInt(d.first, 10), "last_sequence": strconv.FormatInt(d.last, 10)},
	})
	if err != nil {
		return err
	}
	return s.add([]map[string]any{env}, "", nil)
}

func (s *Spool) filteredStats(sources []Source) map[string]int64 {
	return s.counters("filtered:", sources)
}

func (s *Spool) notEvidenceStats(sources []Source) map[string]int64 {
	return s.counters("not_evidence:", sources)
}

func (s *Spool) counters(prefix string, sources []Source) map[string]int64 {
	result := map[string]int64{}
	s.db.View(func(t *bolt.Tx) error {
		for _, source := range sources {
			result[source.Name] = integer(t.Bucket(meta).Get([]byte(prefix + source.Name)))
		}
		return nil
	})
	return result
}
