package tests

import (
	"math"
	"github.com/leonardomb1/pulse/node"
	"testing"
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
		{"4353db8f32bad580", "10.100.67.83"},
		{"20c6d3c9238f80c2", "10.100.32.198"},
		{"f752d605d4522bfb", "10.100.247.82"},
		{"", "10.100.0.1"},           // empty fallback
		{"ab", "10.100.0.1"},          // too short
	}
	for _, tt := range tests {
		got := node.MeshIPFromNodeID(tt.nodeID).String()
		if got != tt.want {
			t.Errorf("MeshIPFromNodeID(%q) = %s, want %s", tt.nodeID, got, tt.want)
		}
	}
}
