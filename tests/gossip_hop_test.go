package tests

import (
	"github.com/leonardomb1/pulse/node"
	"testing"
	"time"
)

func TestDirectLinkNotOverwrittenByGossip(t *testing.T) {
	// Simulates: Node B has a direct link to Node A (hop 0).
	// Then gossip arrives with A's entry at hop 1 (fresher timestamp).
	// The hop-0 entry should NOT be overwritten.

	tbl := node.NewTable()

	// Direct handshake sets hop 0.
	tbl.Upsert(node.PeerEntry{
		NodeID:   "nodeA",
		Addr:     "a:8443",
		LastSeen: time.Now(),
		HopCount: 0,
	})

	e, _ := tbl.Get("nodeA")
	if e.HopCount != 0 {
		t.Fatalf("initial hop should be 0, got %d", e.HopCount)
	}

	// 1 second later, gossip arrives with nodeA at hop 1 (fresher timestamp).
	time.Sleep(10 * time.Millisecond)
	tbl.Upsert(node.PeerEntry{
		NodeID:   "nodeA",
		Addr:     "a:8443",
		LastSeen: time.Now(), // fresher
		HopCount: 1,          // but worse hop count
	})

	e, _ = tbl.Get("nodeA")
	if e.HopCount != 0 {
		t.Fatalf("direct link (hop 0) should not be overwritten by gossip (hop 1), got hop %d", e.HopCount)
	}
}

func TestDirectLinkProtectedEvenWhenStale(t *testing.T) {
	// A direct link (hop 0) is never overwritten by gossip (hop > 0).
	// Dead direct links are cleaned up by the pruner instead.

	tbl := node.NewTable()

	// Direct handshake, even if old.
	tbl.UpsertForce(node.PeerEntry{
		NodeID:   "nodeA",
		Addr:     "a:8443",
		LastSeen: time.Now().Add(-2 * time.Minute),
		HopCount: 0,
	})

	// Gossip arrives with nodeA at hop 1, fresher timestamp.
	tbl.Upsert(node.PeerEntry{
		NodeID:   "nodeA",
		Addr:     "a:8443",
		LastSeen: time.Now(),
		HopCount: 1,
	})

	e, _ := tbl.Get("nodeA")
	if e.HopCount != 0 {
		t.Fatalf("direct link should be protected even when stale, got hop %d", e.HopCount)
	}
}

func TestLowerHopCountAlwaysWins(t *testing.T) {
	// A lower hop count should always overwrite a higher one.

	tbl := node.NewTable()

	tbl.Upsert(node.PeerEntry{
		NodeID:   "nodeA",
		Addr:     "a:8443",
		LastSeen: time.Now(),
		HopCount: 3,
	})

	// Better path found (hop 1).
	tbl.Upsert(node.PeerEntry{
		NodeID:   "nodeA",
		Addr:     "a:8443",
		LastSeen: time.Now(),
		HopCount: 1,
	})

	e, _ := tbl.Get("nodeA")
	if e.HopCount != 1 {
		t.Fatalf("lower hop count should win, got %d", e.HopCount)
	}
}

func TestGossipMergeDoesNotOverwriteDirectLinks(t *testing.T) {
	// Full simulation: two nodes, A and B.
	// A has direct link to B (hop 0). B gossips its self-entry.
	// A merges gossip. B's entry should stay at hop 0.

	tableA := node.NewTable()

	// A registers B via direct handshake.
	tableA.Upsert(node.PeerEntry{
		NodeID:   "B",
		Addr:     "b:8443",
		LastSeen: time.Now(),
		HopCount: 0,
	})

	// B's self-entry (what B would gossip about itself).
	bSelf := node.PeerEntry{
		NodeID:   "B",
		Addr:     "b:8443",
		LastSeen: time.Now().Add(5 * time.Second), // fresher (B refreshes its own entry)
		HopCount: 0,                               // B sees itself at hop 0
	}

	// MergeFrom increments hop by 1, so B's entry arrives at hop 1.
	tableA.MergeFrom([]node.PeerEntry{bSelf}, "A")

	e, _ := tableA.Get("B")
	if e.HopCount != 0 {
		t.Fatalf("direct link to B should be preserved at hop 0, got hop %d", e.HopCount)
	}
}

func TestProbeLatencyUpdatesDirectLink(t *testing.T) {
	// After handshake (hop 0), the prober updates latency.
	// The updated entry should keep hop 0.

	tbl := node.NewTable()

	tbl.Upsert(node.PeerEntry{
		NodeID:   "peer",
		Addr:     "peer:8443",
		LastSeen: time.Now(),
		HopCount: 0,
	})

	// Prober updates latency via UpsertForce (same as real prober).
	e, _ := tbl.Get("peer")
	e.LatencyMS = 18.5
	e.LossRate = 0.0
	tbl.UpsertForce(e)

	updated, _ := tbl.Get("peer")
	if updated.HopCount != 0 {
		t.Fatalf("probe update should keep hop 0, got %d", updated.HopCount)
	}
	if updated.LatencyMS != 18.5 {
		t.Fatalf("latency should be 18.5, got %f", updated.LatencyMS)
	}
}
