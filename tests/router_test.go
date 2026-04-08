package tests

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"testing"

	"github.com/leonardomb1/pulse/node"
)

func TestLinkScore(t *testing.T) {
	tests := []struct {
		name    string
		entry   node.PeerEntry
		wantLow float64
		wantHi  float64
	}{
		{"direct low latency", node.PeerEntry{LatencyMS: 5, LossRate: 0, HopCount: 0}, 4, 6},
		{"direct high latency", node.PeerEntry{LatencyMS: 200, LossRate: 0, HopCount: 0}, 199, 201},
		{"lossy link", node.PeerEntry{LatencyMS: 10, LossRate: 0.2, HopCount: 0}, 19, 21},
		{"multi-hop", node.PeerEntry{LatencyMS: 10, LossRate: 0, HopCount: 3}, 18, 20},
		{"no measurement", node.PeerEntry{LatencyMS: 0, LossRate: 0, HopCount: 0}, 499, 501},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := node.LinkScore(tt.entry)
			if score < tt.wantLow || score > tt.wantHi {
				t.Errorf("LinkScore = %f, want [%f, %f]", score, tt.wantLow, tt.wantHi)
			}
		})
	}
}

func TestLinkScorePreferences(t *testing.T) {
	fast2hop := node.LinkScore(node.PeerEntry{LatencyMS: 5, HopCount: 2})
	slow1hop := node.LinkScore(node.PeerEntry{LatencyMS: 200, HopCount: 1})
	if fast2hop >= slow1hop {
		t.Errorf("fast 2-hop (%f) should beat slow 1-hop (%f)", fast2hop, slow1hop)
	}

	clean := node.LinkScore(node.PeerEntry{LatencyMS: 10, LossRate: 0})
	lossy := node.LinkScore(node.PeerEntry{LatencyMS: 10, LossRate: 0.5})
	if lossy <= clean {
		t.Errorf("lossy (%f) should score worse than clean (%f)", lossy, clean)
	}

	infScore := node.LinkScore(node.PeerEntry{LatencyMS: math.Inf(1)})
	nanScore := node.LinkScore(node.PeerEntry{LatencyMS: math.NaN()})
	if math.IsInf(infScore, 0) || math.IsNaN(infScore) {
		t.Errorf("Inf latency should not produce Inf score: %f", infScore)
	}
	if math.IsInf(nanScore, 0) || math.IsNaN(nanScore) {
		t.Errorf("NaN latency should not produce NaN score: %f", nanScore)
	}
}

func TestMeshIPFromNodeID(t *testing.T) {
	tests := []struct {
		nodeID string
		want   string
	}{
		{"4353db8f32bad580", "10.100.255.212"},
		{"20c6d3c9238f80c2", "10.100.50.254"},
		{"f752d605d4522bfb", "10.100.227.188"},
		{"", "10.100.0.1"},   // empty fallback
		{"ab", "10.100.0.1"}, // too short
	}
	for _, tt := range tests {
		got := node.MeshIPFromNodeID(tt.nodeID).String()
		if got != tt.want {
			t.Errorf("MeshIPFromNodeID(%q) = %s, want %s", tt.nodeID, got, tt.want)
		}
	}
}

func TestMeshIPCollisionAvoidance(t *testing.T) {
	cidr := "10.100.0.0/24"
	const n = 50
	ids := make([]string, n)
	for i := range ids {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		ids[i] = hex.EncodeToString(b)
	}

	seen := make(map[string]string, n) // ip -> nodeID
	collisions := 0
	for _, id := range ids {
		ip := node.MeshIPFromNodeIDWithCIDR(id, cidr).String()

		// Must never be network or broadcast address.
		if ip == "10.100.0.0" {
			t.Errorf("node %s got network address %s", id, ip)
		}
		if ip == "10.100.0.255" {
			t.Errorf("node %s got broadcast address %s", id, ip)
		}

		if prev, exists := seen[ip]; exists {
			collisions++
			t.Logf("collision: %s and %s both got %s", prev, id, ip)
		}
		seen[ip] = id
	}
	// With FNV-1a and 50 nodes in 254 slots, birthday paradox expects ~5 collisions.
	// Allow up to 12 to avoid flaky test failures from normal variance.
	if collisions > 12 {
		t.Errorf("too many collisions: %d out of %d nodes (expected ~5)", collisions, n)
	}
}

func TestMeshIPBroadcastAvoidance(t *testing.T) {
	// Test a /24 CIDR — ensure no .0 or .255 addresses are produced.
	cidr := "10.200.1.0/24"
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("%016x", i)
		ip := node.MeshIPFromNodeIDWithCIDR(id, cidr)
		if ip.Equal([]byte{10, 200, 1, 0}) {
			t.Errorf("nodeID %q produced network address %s", id, ip)
		}
		if ip.Equal([]byte{10, 200, 1, 255}) {
			t.Errorf("nodeID %q produced broadcast address %s", id, ip)
		}
	}

	// Test a /16 CIDR — ensure no .0.0 or .255.255 addresses.
	cidr16 := "172.16.0.0/16"
	for i := 0; i < 1000; i++ {
		id := fmt.Sprintf("%016x", i)
		ip := node.MeshIPFromNodeIDWithCIDR(id, cidr16)
		if ip.String() == "172.16.0.0" {
			t.Errorf("nodeID %q produced network address %s in /16", id, ip)
		}
		if ip.String() == "172.16.255.255" {
			t.Errorf("nodeID %q produced broadcast address %s in /16", id, ip)
		}
	}
}
