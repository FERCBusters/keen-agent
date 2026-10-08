package main

import "testing"

func TestBatchAckLeavesBacklog(t *testing.T) {
	s := testSpool(t)
	events := make([]Event, 2000)
	for i := range events {
		events[i] = event()
	}
	if err := s.add(events, "test", Checkpoint{}); err != nil {
		t.Fatal(err)
	}
	batch, err := s.batch()
	if err != nil || len(batch) != 64 {
		t.Fatalf("batch=%d err=%v", len(batch), err)
	}
	ids := map[string]bool{}
	for _, e := range batch {
		ids[e.ID] = true
	}
	if err = s.ack(ids); err != nil {
		t.Fatal(err)
	}
	n, _, _ := s.stats()
	if n != 1936 {
		t.Fatal(n)
	}
	next, err := s.batch()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range next {
		if ids[e.ID] {
			t.Fatal("acknowledged event remains")
		}
	}
	if len(ids) != 64 {
		t.Fatal("ack mutated caller map")
	}
}

func TestPurgePreservesCheckpoint(t *testing.T) {
	s := testSpool(t)
	if err := s.add([]Event{event(), event()}, "file", Checkpoint{Offset: 123}); err != nil {
		t.Fatal(err)
	}
	discarded, err := s.purgeQueue()
	if err != nil || discarded != 2 {
		t.Fatalf("%d %v", discarded, err)
	}
	var checkpoint Checkpoint
	if err = s.checkpoint("file", &checkpoint); err != nil || checkpoint.Offset != 123 {
		t.Fatalf("checkpoint %v %v", checkpoint, err)
	}
	n, _, rejected := s.stats()
	if n != 0 || rejected != 2 {
		t.Fatalf("%d %d", n, rejected)
	}
	batch, err := s.batch()
	if err != nil || len(batch) != 0 {
		t.Fatalf("%v %v", batch, err)
	}
	if err = s.add([]Event{event()}, "file", Checkpoint{Offset: 124}); err != nil {
		t.Fatal(err)
	}
	n, _, _ = s.stats()
	if n != 1 {
		t.Fatal(n)
	}
}
