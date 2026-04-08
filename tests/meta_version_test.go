package tests

import (
	"testing"
	"time"

	"github.com/leonardomb1/pulse/node"
)

// TestMetaVersionGossipUpdate verifies that a gossip entry (hop > 0) with a
// newer MetaVersion can update metadata on a hop-0 direct-link entry while
// preserving the routing fields from the direct link.
func TestMetaVersionGossipUpdate(t *testing.T) {
	tbl := node.NewTable()

	now := time.Now()
	tbl.Upsert(node.PeerEntry{
		NodeID:      "peer1",
		Addr:        "10.0.0.1:8443",
		PublicKey:   []byte("key1"),
		MeshIP:      "100.64.0.1",
		MetaVersion: 1,
		LastSeen:    now,
		HopCount:    0,
		LatencyMS:   5.0,
		LossRate:    0.01,
		LinkType:    "quic",
	})

	// Gossip arrives at hop 1 with a newer MetaVersion and different MeshIP.
	tbl.Upsert(node.PeerEntry{
		NodeID:      "peer1",
		Addr:        "99.99.99.99:9999", // should NOT overwrite
		PublicKey:   []byte("newkey"),   // should NOT overwrite
		MeshIP:      "100.64.0.99",      // SHOULD update
		MetaVersion: 2,
		LastSeen:    now.Add(time.Second),
		HopCount:    1,
		LatencyMS:   100.0,       // should NOT overwrite
		LossRate:    0.5,         // should NOT overwrite
		LinkType:    "websocket", // should NOT overwrite
	})

	e, ok := tbl.Get("peer1")
	if !ok {
		t.Fatal("peer1 should exist")
	}

	// Metadata should be updated.
	if e.MeshIP != "100.64.0.99" {
		t.Fatalf("MeshIP: got %q, want %q", e.MeshIP, "100.64.0.99")
	}
	if e.MetaVersion != 2 {
		t.Fatalf("MetaVersion: got %d, want 2", e.MetaVersion)
	}

	// Routing fields should be preserved from the original hop-0 entry.
	if e.Addr != "10.0.0.1:8443" {
		t.Fatalf("Addr should be preserved: got %q, want %q", e.Addr, "10.0.0.1:8443")
	}
	if string(e.PublicKey) != "key1" {
		t.Fatalf("PublicKey should be preserved: got %q, want %q", string(e.PublicKey), "key1")
	}
	if e.HopCount != 0 {
		t.Fatalf("HopCount should be preserved: got %d, want 0", e.HopCount)
	}
	if e.LatencyMS != 5.0 {
		t.Fatalf("LatencyMS should be preserved: got %f, want 5.0", e.LatencyMS)
	}
	if e.LossRate != 0.01 {
		t.Fatalf("LossRate should be preserved: got %f, want 0.01", e.LossRate)
	}
	if e.LinkType != "quic" {
		t.Fatalf("LinkType should be preserved: got %q, want %q", e.LinkType, "quic")
	}
}

// TestMetaVersionNoDowngrade verifies that a gossip entry with an older
// MetaVersion cannot overwrite a hop-0 entry.
func TestMetaVersionNoDowngrade(t *testing.T) {
	tbl := node.NewTable()

	now := time.Now()
	tbl.Upsert(node.PeerEntry{
		NodeID:      "peer1",
		Addr:        "10.0.0.1:8443",
		MeshIP:      "100.64.0.1",
		MetaVersion: 2,
		LastSeen:    now,
		HopCount:    0,
	})

	// Gossip arrives at hop 1 with an OLDER MetaVersion.
	tbl.Upsert(node.PeerEntry{
		NodeID:      "peer1",
		Addr:        "99.99.99.99:9999",
		MeshIP:      "100.64.0.99",
		MetaVersion: 1,
		LastSeen:    now.Add(time.Second),
		HopCount:    1,
	})

	e, ok := tbl.Get("peer1")
	if !ok {
		t.Fatal("peer1 should exist")
	}

	// Nothing should have changed.
	if e.MeshIP != "100.64.0.1" {
		t.Fatalf("MeshIP should not be updated: got %q, want %q", e.MeshIP, "100.64.0.1")
	}
	if e.MetaVersion != 2 {
		t.Fatalf("MetaVersion should not be downgraded: got %d, want 2", e.MetaVersion)
	}
	if e.Addr != "10.0.0.1:8443" {
		t.Fatalf("Addr should not be changed: got %q, want %q", e.Addr, "10.0.0.1:8443")
	}
	if e.HopCount != 0 {
		t.Fatalf("HopCount should remain 0: got %d", e.HopCount)
	}
}

// TestMetaVersionEqualNoUpdate verifies that equal MetaVersion does not
// bypass hop-0 protection.
func TestMetaVersionEqualNoUpdate(t *testing.T) {
	tbl := node.NewTable()

	now := time.Now()
	tbl.Upsert(node.PeerEntry{
		NodeID:      "peer1",
		Addr:        "10.0.0.1:8443",
		MeshIP:      "100.64.0.1",
		MetaVersion: 1,
		LastSeen:    now,
		HopCount:    0,
	})

	// Gossip arrives at hop 1 with the SAME MetaVersion.
	tbl.Upsert(node.PeerEntry{
		NodeID:      "peer1",
		Addr:        "99.99.99.99:9999",
		MeshIP:      "100.64.0.99",
		MetaVersion: 1,
		LastSeen:    now.Add(time.Second),
		HopCount:    1,
	})

	e, _ := tbl.Get("peer1")
	if e.MeshIP != "100.64.0.1" {
		t.Fatalf("MeshIP should not be updated with equal MetaVersion: got %q", e.MeshIP)
	}
}
