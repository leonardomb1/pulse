package tests

import (
	"github.com/leonardomb1/pulse/node"
	"testing"
	"time"
)

func TestSelfEntryDoesNotGoStale(t *testing.T) {
	tbl := node.NewTable()

	// Simulate a self-entry created at startup.
	tbl.UpsertForce(node.PeerEntry{
		NodeID:   "self",
		Addr:     "localhost:8443",
		LastSeen: time.Now(),
		HopCount: 0,
	})

	// Simulate a peer entry.
	tbl.UpsertForce(node.PeerEntry{
		NodeID:   "peer1",
		Addr:     "1.2.3.4:8443",
		LastSeen: time.Now(),
		HopCount: 1,
	})

	// Fast-forward: pretend 6 minutes pass without refreshing.
	// Manually set stale timestamps.
	staleTime := time.Now().Add(-6 * time.Minute)

	tbl.UpsertForce(node.PeerEntry{
		NodeID:   "self",
		Addr:     "localhost:8443",
		LastSeen: staleTime,
		HopCount: 0,
	})
	tbl.UpsertForce(node.PeerEntry{
		NodeID:   "peer1",
		Addr:     "1.2.3.4:8443",
		LastSeen: staleTime,
		HopCount: 1,
	})

	// Prune should remove peer1 but NOT self.
	tbl.PruneStale("self")

	if _, ok := tbl.Get("self"); !ok {
		t.Fatal("self entry should never be pruned")
	}
	if _, ok := tbl.Get("peer1"); ok {
		t.Fatal("stale peer1 should be pruned")
	}
}

func TestSelfEntryRefreshPreventsRemotePrune(t *testing.T) {
	// Simulates the bug: two nodes, each with their own table.
	// If node A doesn't refresh its self-entry, node B prunes A after 5 minutes.

	tableA := node.NewTable()
	tableB := node.NewTable()

	// Node A creates its self-entry.
	entryA := node.PeerEntry{
		NodeID:   "nodeA",
		Addr:     "a:8443",
		LastSeen: time.Now(),
		HopCount: 0,
	}
	tableA.UpsertForce(entryA)

	// Node B receives A's entry via gossip.
	tableB.MergeFrom([]node.PeerEntry{entryA}, "nodeB")

	// Verify B sees A.
	if _, ok := tableB.Get("nodeA"); !ok {
		t.Fatal("B should see A after gossip")
	}

	// Simulate 6 minutes without gossip refresh.
	staleA := entryA
	staleA.LastSeen = time.Now().Add(-6 * time.Minute)
	tableB.UpsertForce(staleA) // force the stale timestamp

	// B prunes — A should be gone (this is the bug scenario).
	tableB.PruneStale("nodeB")
	if _, ok := tableB.Get("nodeA"); ok {
		t.Fatal("stale nodeA should be pruned from B's table")
	}

	// Now simulate the fix: A refreshes its LastSeen before gossip push.
	freshA := entryA
	freshA.LastSeen = time.Now()
	tableA.UpsertForce(freshA)

	// A pushes to B again.
	tableB.MergeFrom(tableA.Snapshot(), "nodeB")

	// B should see A again with fresh timestamp.
	got, ok := tableB.Get("nodeA")
	if !ok {
		t.Fatal("B should see A after fresh gossip")
	}
	if time.Since(got.LastSeen) > 1*time.Second {
		t.Errorf("A's LastSeen should be fresh, got %v ago", time.Since(got.LastSeen))
	}
}

func TestDeltaGossipSendsRefreshedSelfEntry(t *testing.T) {
	tbl := node.NewTable()

	// Initial self-entry.
	tbl.UpsertForce(node.PeerEntry{
		NodeID:   "self",
		Addr:     "me:8443",
		LastSeen: time.Now(),
		HopCount: 0,
	})
	v1 := tbl.Version()

	// Nothing changed — SnapshotSince should be empty.
	delta := tbl.SnapshotSince(v1)
	if len(delta) != 0 {
		t.Errorf("expected 0 delta entries, got %d", len(delta))
	}

	// Refresh self-entry (simulates what pushGossip now does).
	self, _ := tbl.Get("self")
	self.LastSeen = time.Now()
	tbl.UpsertForce(self)
	v2 := tbl.Version()

	if v2 <= v1 {
		t.Fatal("version should increment after UpsertForce")
	}

	// Now SnapshotSince(v1) should include the refreshed self-entry.
	delta = tbl.SnapshotSince(v1)
	if len(delta) != 1 || delta[0].NodeID != "self" {
		t.Errorf("expected 1 delta entry (self), got %d", len(delta))
	}
}
