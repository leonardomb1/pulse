package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/leonardomb1/pulse/node"
)

func TestStatsRingRecordAndGet(t *testing.T) {
	ring := node.NewStatsRing()

	for i := 0; i < 5; i++ {
		ring.Record("peer-a", node.StatsSnapshot{
			Timestamp: time.Now(),
			LatencyMS: float64(i),
		})
	}

	snaps := ring.Get("peer-a")
	if len(snaps) != 5 {
		t.Fatalf("expected 5 snapshots, got %d", len(snaps))
	}
	// Should be chronological.
	for i := 0; i < 5; i++ {
		if snaps[i].LatencyMS != float64(i) {
			t.Errorf("snap[%d].LatencyMS = %.1f, want %d", i, snaps[i].LatencyMS, i)
		}
	}

	// Non-existent peer.
	if snaps := ring.Get("no-such"); snaps != nil {
		t.Errorf("expected nil for unknown peer, got %d snaps", len(snaps))
	}
}

func TestStatsRingWraparound(t *testing.T) {
	ring := node.NewStatsRing()

	// Write more than ring size (360).
	for i := 0; i < 400; i++ {
		ring.Record("peer-b", node.StatsSnapshot{
			Timestamp: time.Now(),
			LatencyMS: float64(i),
		})
	}

	snaps := ring.Get("peer-b")
	if len(snaps) != 360 {
		t.Fatalf("expected 360 snapshots after wraparound, got %d", len(snaps))
	}
	// First snapshot should be i=40 (oldest surviving).
	if snaps[0].LatencyMS != 40 {
		t.Errorf("oldest snapshot LatencyMS = %.0f, want 40", snaps[0].LatencyMS)
	}
	// Last snapshot should be i=399.
	if snaps[359].LatencyMS != 399 {
		t.Errorf("newest snapshot LatencyMS = %.0f, want 399", snaps[359].LatencyMS)
	}
}

func TestStatsRingAllLatest(t *testing.T) {
	ring := node.NewStatsRing()

	ring.Record("a", node.StatsSnapshot{LatencyMS: 10})
	ring.Record("a", node.StatsSnapshot{LatencyMS: 20})
	ring.Record("b", node.StatsSnapshot{LatencyMS: 5})

	latest := ring.AllLatest()
	if latest["a"].LatencyMS != 20 {
		t.Errorf("a latest = %.0f, want 20", latest["a"].LatencyMS)
	}
	if latest["b"].LatencyMS != 5 {
		t.Errorf("b latest = %.0f, want 5", latest["b"].LatencyMS)
	}
}

func TestStatsRingPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")

	ring1 := node.NewStatsRing()
	ring1.Record("peer-x", node.StatsSnapshot{BytesIn: 1000, BytesOut: 2000})
	ring1.Record("peer-y", node.StatsSnapshot{BytesIn: 500, BytesOut: 800})

	if err := ring1.SaveCumulative(path); err != nil {
		t.Fatal(err)
	}

	// Verify file exists.
	if _, err := os.Stat(path); err != nil {
		t.Fatal("stats file not created")
	}

	// Load into a new ring.
	ring2 := node.NewStatsRing()
	if err := ring2.LoadCumulative(path); err != nil {
		t.Fatal(err)
	}

	latest := ring2.AllLatest()
	if latest["peer-x"].BytesIn != 1000 || latest["peer-x"].BytesOut != 2000 {
		t.Errorf("peer-x: got %+v", latest["peer-x"])
	}
	if latest["peer-y"].BytesIn != 500 {
		t.Errorf("peer-y: got %+v", latest["peer-y"])
	}
}
