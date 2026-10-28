package nativeposture

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"keen-agent/internal/ueu"

	bolt "go.etcd.io/bbolt"
)

func TestReportsQueuedByEarlierVersionsAreDropped(t *testing.T) {
	db, err := bolt.Open(filepath.Join(t.TempDir(), "pending.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sealed, _ := json.Marshal(ueu.Sealed{EvidenceID: "01a18003-5e44-793b-8cfc-f08102698f20", Canonical: []byte("{}"), Hash: "sha256:00"})
	db.Update(func(tx *bolt.Tx) error {
		b, _ := tx.CreateBucketIfNotExists([]byte("pending"))
		// KEEN Agent 0.1 queued whole OTLP requests.
		b.Put([]byte("00000000000000000001"), []byte(`{"resourceLogs":[]}`))
		b.Put([]byte("00000000000000000002"), sealed)
		return nil
	})
	if err := dropEarlierReports(db); err != nil {
		t.Fatal(err)
	}
	keys, batch, err := pending(db)
	if err != nil || len(keys) != 1 || batch[0].EvidenceID == "" {
		t.Fatal(keys, batch, err)
	}
	// A queue without the bucket is left alone.
	empty, _ := bolt.Open(filepath.Join(t.TempDir(), "pending.db"), 0600, nil)
	defer empty.Close()
	if err := dropEarlierReports(empty); err != nil {
		t.Fatal(err)
	}
}
