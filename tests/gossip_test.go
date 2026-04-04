package tests

import (
	"github.com/leonardomb1/pulse/node"
	"testing"
	"time"
)

func TestTableUpsert(t *testing.T) {
	tbl := node.NewTable()

	tbl.Upsert(node.PeerEntry{NodeID: "a", Addr: "1.2.3.4:8443", LastSeen: time.Now(), HopCount: 2})
	e, ok := tbl.Get("a")
	if !ok || e.Addr != "1.2.3.4:8443" {
		t.Fatalf("expected entry, got ok=%v addr=%s", ok, e.Addr)
	}

	// Fresher timestamp wins.
	tbl.Upsert(node.PeerEntry{NodeID: "a", Addr: "5.6.7.8:8443", LastSeen: time.Now(), HopCount: 2})
	e, _ = tbl.Get("a")
	if e.Addr != "5.6.7.8:8443" {
		t.Fatalf("expected updated addr, got %s", e.Addr)
	}

	// Lower hop count wins.
	ts := time.Now()
	tbl.Upsert(node.PeerEntry{NodeID: "a", Addr: "old:8443", LastSeen: ts, HopCount: 5})
	tbl.Upsert(node.PeerEntry{NodeID: "a", Addr: "closer:8443", LastSeen: ts, HopCount: 1})
	e, _ = tbl.Get("a")
	if e.Addr != "closer:8443" {
		t.Fatalf("expected closer hop to win, got %s", e.Addr)
	}
}

func TestTableMaxHopCount(t *testing.T) {
	tbl := node.NewTable()
	tbl.Upsert(node.PeerEntry{NodeID: "far", HopCount: 20})
	if _, ok := tbl.Get("far"); ok {
		t.Fatal("entry with hopcount > 16 should be rejected")
	}
}

func TestMergeFrom(t *testing.T) {
	tbl := node.NewTable()
	tbl.Upsert(node.PeerEntry{NodeID: "self", Addr: "me:8443", HopCount: 0})

	incoming := []node.PeerEntry{
		{NodeID: "self", Addr: "should-be-skipped", HopCount: 0},
		{NodeID: "peer1", Addr: "peer1:8443", HopCount: 1, LastSeen: time.Now()},
	}
	tbl.MergeFrom(incoming, "self")

	e, _ := tbl.Get("self")
	if e.Addr != "me:8443" {
		t.Fatalf("self should not be overwritten, got %s", e.Addr)
	}

	e, ok := tbl.Get("peer1")
	if !ok || e.HopCount != 2 {
		t.Fatalf("peer1: ok=%v hopcount=%d, want 2", ok, e.HopCount)
	}
}

func TestPruneStale(t *testing.T) {
	tbl := node.NewTable()
	tbl.Upsert(node.PeerEntry{NodeID: "self", LastSeen: time.Now(), HopCount: 0})
	tbl.Upsert(node.PeerEntry{NodeID: "fresh", LastSeen: time.Now(), HopCount: 1})
	tbl.Upsert(node.PeerEntry{NodeID: "stale", LastSeen: time.Now().Add(-10 * time.Minute), HopCount: 1})

	tbl.PruneStale("self")

	if _, ok := tbl.Get("self"); !ok {
		t.Fatal("self should never be pruned")
	}
	if _, ok := tbl.Get("fresh"); !ok {
		t.Fatal("fresh peer should not be pruned")
	}
	if _, ok := tbl.Get("stale"); ok {
		t.Fatal("stale peer should be pruned")
	}
}

func TestFindCA(t *testing.T) {
	tbl := node.NewTable()
	tbl.Upsert(node.PeerEntry{NodeID: "relay", HopCount: 0})
	tbl.Upsert(node.PeerEntry{NodeID: "ca-node", IsCA: true, HopCount: 1})

	ca, ok := tbl.FindCA()
	if !ok || ca.NodeID != "ca-node" {
		t.Fatalf("FindCA: ok=%v nodeID=%s", ok, ca.NodeID)
	}
}

func TestExitNodes(t *testing.T) {
	tbl := node.NewTable()
	tbl.Upsert(node.PeerEntry{NodeID: "relay", HopCount: 0})
	tbl.Upsert(node.PeerEntry{NodeID: "exit1", IsExit: true, ExitCIDRs: []string{"0.0.0.0/0"}, HopCount: 1})

	exits := tbl.ExitNodes()
	if len(exits) != 1 || exits[0].NodeID != "exit1" {
		t.Fatalf("ExitNodes: got %d, want 1", len(exits))
	}
}
