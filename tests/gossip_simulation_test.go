package tests

import (
	"github.com/leonardomb1/pulse/node"
	"testing"
	"time"
)

// TestFullGossipSimulation simulates the real-world scenario that caused
// the latency/hop bug: two nodes connected via QUIC, exchanging gossip
// every 10 seconds, with self-entry refresh on each round.
func TestFullGossipSimulation(t *testing.T) {
	tableA := node.NewTable()
	tableB := node.NewTable()

	// === Initial setup (what happens at node startup) ===

	// Node A's self-entry.
	tableA.UpsertForce(node.PeerEntry{
		NodeID:   "A",
		Addr:     "a:8443",
		LastSeen: time.Now(),
		HopCount: 0,
		IsScribe: true,
	})

	// Node B's self-entry.
	tableB.UpsertForce(node.PeerEntry{
		NodeID:   "B",
		Addr:     "b:443",
		LastSeen: time.Now(),
		HopCount: 0,
		IsCA:     true,
	})

	// === Handshake: A connects to B ===
	// Both sides register each other at hop 0.
	tableA.Upsert(node.PeerEntry{
		NodeID:   "B",
		Addr:     "b:443",
		LastSeen: time.Now(),
		HopCount: 0,
		IsCA:     true,
	})
	tableB.Upsert(node.PeerEntry{
		NodeID:   "A",
		Addr:     "a:8443",
		LastSeen: time.Now(),
		HopCount: 0,
		IsScribe: true,
	})

	// Verify initial state: both see each other at hop 0.
	assertHop(t, tableA, "B", "after handshake, A sees B")
	assertHop(t, tableB, "A", "after handshake, B sees A")

	// === Simulate 10 gossip rounds (100 seconds) ===
	for round := 0; round < 10; round++ {
		// Each node refreshes its self-entry (the pushGossip fix).
		selfA, _ := tableA.Get("A")
		selfA.LastSeen = time.Now()
		tableA.UpsertForce(selfA)

		selfB, _ := tableB.Get("B")
		selfB.LastSeen = time.Now()
		tableB.UpsertForce(selfB)

		// A sends its full table to B. MergeFrom increments hop by 1.
		tableB.MergeFrom(tableA.Snapshot(), "B")

		// B sends its full table to A. MergeFrom increments hop by 1.
		tableA.MergeFrom(tableB.Snapshot(), "A")

		// After every round, both should still see each other at hop 0.
		assertHop(t, tableA, "B", "round %d: A sees B", round)
		assertHop(t, tableB, "A", "round %d: B sees A", round)
	}

	// === Simulate prober updating latency ===
	entryB, _ := tableA.Get("B")
	entryB.LatencyMS = 18.5
	entryB.LossRate = 0.01
	entryB.LastSeen = time.Now()
	tableA.Upsert(entryB)

	got, _ := tableA.Get("B")
	if got.HopCount != 0 {
		t.Fatalf("after prober update, A should see B at hop 0, got %d", got.HopCount)
	}
	if got.LatencyMS != 18.5 {
		t.Fatalf("latency should be 18.5, got %f", got.LatencyMS)
	}

	// === More gossip rounds after prober ===
	for round := 0; round < 5; round++ {
		selfA, _ := tableA.Get("A")
		selfA.LastSeen = time.Now()
		tableA.UpsertForce(selfA)

		selfB, _ := tableB.Get("B")
		selfB.LastSeen = time.Now()
		tableB.UpsertForce(selfB)

		tableB.MergeFrom(tableA.Snapshot(), "B")
		tableA.MergeFrom(tableB.Snapshot(), "A")

		assertHop(t, tableA, "B", "post-prober round %d: A sees B", round)
		assertHop(t, tableB, "A", "post-prober round %d: B sees A", round)
	}

	// Latency should still be preserved after gossip rounds.
	final, _ := tableA.Get("B")
	if final.LatencyMS != 18.5 {
		t.Fatalf("latency lost after gossip rounds: got %f", final.LatencyMS)
	}
}

// TestDeltaGossipSimulation tests that delta-gossip correctly sends
// refreshed self-entries and doesn't cause hop escalation.
func TestDeltaGossipSimulation(t *testing.T) {
	tableA := node.NewTable()
	tableB := node.NewTable()

	// Setup.
	tableA.UpsertForce(node.PeerEntry{NodeID: "A", Addr: "a:8443", LastSeen: time.Now(), HopCount: 0})
	tableB.UpsertForce(node.PeerEntry{NodeID: "B", Addr: "b:443", LastSeen: time.Now(), HopCount: 0})

	// Handshake.
	tableA.Upsert(node.PeerEntry{NodeID: "B", Addr: "b:443", LastSeen: time.Now(), HopCount: 0})
	tableB.Upsert(node.PeerEntry{NodeID: "A", Addr: "a:8443", LastSeen: time.Now(), HopCount: 0})

	versionA := tableA.Version()
	versionB := tableB.Version()

	// Round 1: only self-entry changed (refresh). Delta should include it.
	selfA, _ := tableA.Get("A")
	selfA.LastSeen = time.Now()
	tableA.UpsertForce(selfA)

	deltaA := tableA.SnapshotSince(versionA)
	if len(deltaA) != 1 || deltaA[0].NodeID != "A" {
		t.Fatalf("delta should have 1 entry (self refresh), got %d", len(deltaA))
	}

	// B merges delta from A.
	tableB.MergeFrom(deltaA, "B")
	assertHop(t, tableB, "A", "delta round 1: B sees A")

	// Round 2: B refreshes self.
	selfB, _ := tableB.Get("B")
	selfB.LastSeen = time.Now()
	tableB.UpsertForce(selfB)

	deltaB := tableB.SnapshotSince(versionB)
	tableA.MergeFrom(deltaB, "A")
	assertHop(t, tableA, "B", "delta round 2: A sees B")

	// 10 more delta rounds.
	for i := 0; i < 10; i++ {
		va := tableA.Version()
		vb := tableB.Version()

		sa, _ := tableA.Get("A")
		sa.LastSeen = time.Now()
		tableA.UpsertForce(sa)

		sb, _ := tableB.Get("B")
		sb.LastSeen = time.Now()
		tableB.UpsertForce(sb)

		tableB.MergeFrom(tableA.SnapshotSince(va), "B")
		tableA.MergeFrom(tableB.SnapshotSince(vb), "A")

		assertHop(t, tableA, "B", "delta round %d: A sees B", i)
		assertHop(t, tableB, "A", "delta round %d: B sees A", i)
	}
}

// TestThreeNodeGossipPropagation tests that a 3-node mesh correctly
// propagates entries: A↔B↔C (A has no direct link to C).
func TestThreeNodeGossipPropagation(t *testing.T) {
	tableA := node.NewTable()
	tableB := node.NewTable()
	tableC := node.NewTable()

	// Self-entries.
	tableA.UpsertForce(node.PeerEntry{NodeID: "A", Addr: "a:8443", LastSeen: time.Now(), HopCount: 0})
	tableB.UpsertForce(node.PeerEntry{NodeID: "B", Addr: "b:8443", LastSeen: time.Now(), HopCount: 0})
	tableC.UpsertForce(node.PeerEntry{NodeID: "C", Addr: "c:8443", LastSeen: time.Now(), HopCount: 0})

	// Handshakes: A↔B and B↔C (A has no direct link to C).
	tableA.Upsert(node.PeerEntry{NodeID: "B", Addr: "b:8443", LastSeen: time.Now(), HopCount: 0})
	tableB.Upsert(node.PeerEntry{NodeID: "A", Addr: "a:8443", LastSeen: time.Now(), HopCount: 0})
	tableB.Upsert(node.PeerEntry{NodeID: "C", Addr: "c:8443", LastSeen: time.Now(), HopCount: 0})
	tableC.Upsert(node.PeerEntry{NodeID: "B", Addr: "b:8443", LastSeen: time.Now(), HopCount: 0})

	// Round 1: gossip A↔B, B↔C.
	tableB.MergeFrom(tableA.Snapshot(), "B")
	tableA.MergeFrom(tableB.Snapshot(), "A")
	tableC.MergeFrom(tableB.Snapshot(), "C")
	tableB.MergeFrom(tableC.Snapshot(), "B")

	// A should see C at hop 2 (A→B at 0, B has C at 0, gossip adds +1 each hop).
	eC, ok := tableA.Get("C")
	if !ok {
		t.Fatal("A should know about C after gossip")
	}
	if eC.HopCount < 1 {
		t.Fatalf("A should see C at hop >= 1, got %d", eC.HopCount)
	}

	// Direct links should be preserved.
	assertHop(t, tableA, "B", "A↔B direct")
	assertHop(t, tableB, "A", "B↔A direct")
	assertHop(t, tableB, "C", "B↔C direct")
	assertHop(t, tableC, "B", "C↔B direct")
}

func assertHop(t *testing.T, tbl *node.Table, nodeID string, msgFormat string, args ...interface{}) {
	t.Helper()
	e, ok := tbl.Get(nodeID)
	if !ok {
		t.Fatalf(msgFormat+": node %s not found", append(args, nodeID)...)
	}
	if e.HopCount != 0 {
		t.Fatalf(msgFormat+": expected hop 0, got %d", append(args, e.HopCount)...)
	}
}
