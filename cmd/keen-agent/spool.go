package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"time"
)

var full = errors.New("queue full: collection paused until delivery frees space")
var q = []byte("queue")
var cp = []byte("checkpoints")
var meta = []byte("meta")

type Event struct {
	AgentVersion string            `json:"agent_version"`
	ID           string            `json:"id"`
	Timestamp    time.Time         `json:"timestamp"`
	Source       string            `json:"source"`
	Actor        string            `json:"actor,omitempty"`
	Action       string            `json:"action"`
	Outcome      string            `json:"outcome"`
	Severity     int               `json:"severity"`
	Summary      string            `json:"summary"`
	Raw          string            `json:"raw"`
	Fields       map[string]string `json:"fields"`
}
type queued struct {
	Event Event     `json:"event"`
	Added time.Time `json:"added"`
}
type Spool struct {
	db    *bolt.DB
	limit int64
}

func uuid() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
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
func (s *Spool) add(events []Event, key string, state any, filtered ...filterTally) error {
	return s.db.Update(func(t *bolt.Tx) error {
		m := t.Bucket(meta)
		for _, tally := range filtered {
			if tally.count > 0 {
				key := "filtered:" + tally.source
				if err := putInt(m, key, integer(m.Get([]byte(key)))+tally.count); err != nil {
					return err
				}
			}
		}
		size := integer(m.Get([]byte("bytes")))
		count := integer(m.Get([]byte("count")))
		queue := t.Bucket(q)
		for _, e := range events {
			if e.AgentVersion == "" {
				e.AgentVersion = version
			}
			b, err := json.Marshal(queued{e, time.Now().UTC()})
			if err != nil {
				return err
			}
			size += int64(len(b))
			if size > s.limit {
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
			count++
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
func (s *Spool) batch() ([]Event, error) {
	out := []Event{}
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
			out = append(out, r.Event)
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
			if remaining[r.Event.ID] {
				keys = append(keys, append([]byte(nil), k...))
				size -= int64(len(v))
				count--
				delete(remaining, r.Event.ID)
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
func (s *Spool) expire(days int) error {
	if days == 0 {
		return nil
	}
	return s.db.Update(func(t *bolt.Tx) error {
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
}

// purgeQueue deliberately discards pending delivery without resetting read positions.
func (s *Spool) purgeQueue() (int64, error) {
	var discarded int64
	err := s.db.Update(func(t *bolt.Tx) error {
		m := t.Bucket(meta)
		discarded = integer(m.Get([]byte("count")))
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
		return putInt(m, "rejected", integer(m.Get([]byte("rejected")))+discarded)
	})
	return discarded, err
}

func (s *Spool) filteredStats(sources []Source) map[string]int64 {
	result := map[string]int64{}
	s.db.View(func(t *bolt.Tx) error {
		for _, source := range sources {
			result[source.Name] = integer(t.Bucket(meta).Get([]byte("filtered:" + source.Name)))
		}
		return nil
	})
	return result
}
