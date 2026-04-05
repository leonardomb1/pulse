package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leonardomb1/pulse/node"
)

func TestEventLogEmitAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")

	el, err := node.OpenEventLog(path)
	if err != nil {
		t.Fatal(err)
	}

	el.Emit(node.EventEntry{Type: node.EventStartup, Detail: "node started"})
	el.Emit(node.EventEntry{Type: node.EventLinkUp, NodeID: "node1", Detail: "quic"})
	el.Emit(node.EventEntry{Type: node.EventLinkDown, NodeID: "node2", Detail: "timeout"})
	el.Emit(node.EventEntry{Type: node.EventCertIssued, NodeID: "node1"})
	el.Flush()

	// Read all.
	events, err := node.ReadFiltered(path, node.FilterOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	// Filter by type.
	events, _ = node.ReadFiltered(path, node.FilterOpts{Type: node.EventLinkUp})
	if len(events) != 1 || events[0].NodeID != "node1" {
		t.Errorf("type filter: got %d events", len(events))
	}

	// Filter by node.
	events, _ = node.ReadFiltered(path, node.FilterOpts{Node: "node2"})
	if len(events) != 1 || events[0].Type != node.EventLinkDown {
		t.Errorf("node filter: got %d events", len(events))
	}

	// Filter by time.
	events, _ = node.ReadFiltered(path, node.FilterOpts{Since: time.Now().Add(1 * time.Hour)})
	if len(events) != 0 {
		t.Errorf("since filter: expected 0 future events, got %d", len(events))
	}

	_ = el.Close()
}

func TestEventLogSubscribe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")

	el, err := node.OpenEventLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer el.Close()

	ch := el.Subscribe()
	defer el.Unsubscribe(ch)

	el.Emit(node.EventEntry{Type: node.EventLinkUp, NodeID: "peer1"})

	select {
	case e := <-ch:
		if e.Type != node.EventLinkUp || e.NodeID != "peer1" {
			t.Errorf("unexpected event: %+v", e)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("subscriber did not receive event")
	}
}

func TestEventLogRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")

	el, err := node.OpenEventLog(path)
	if err != nil {
		t.Fatal(err)
	}

	// Write enough data to trigger rotation (>10MB).
	bigDetail := strings.Repeat("x", 10000)
	for i := 0; i < 1100; i++ {
		el.Emit(node.EventEntry{Type: node.EventStartup, Detail: bigDetail})
	}
	el.Flush()
	_ = el.Close()

	// The rotated file should exist.
	if _, err := os.Stat(path + ".1"); os.IsNotExist(err) {
		t.Error("rotated file not created")
	}

	// The current file should be small (post-rotation writes).
	info, _ := os.Stat(path)
	if info.Size() > 5*1024*1024 {
		t.Errorf("current file too large after rotation: %d bytes", info.Size())
	}
}
