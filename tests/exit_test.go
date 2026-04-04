package tests

import (
	"github.com/leonardomb1/pulse/node"
	"net"
	"testing"
)

func TestExitRouteLookup(t *testing.T) {
	tbl := node.NewExitRouteTable("/dev/null")
	tbl.Add("10.0.0.0/8", "node-a")
	tbl.Add("10.1.0.0/16", "node-b")
	tbl.Add("0.0.0.0/0", "node-c")

	tests := []struct {
		ip   string
		want string
	}{
		{"10.1.2.3", "node-b"},
		{"10.2.0.1", "node-a"},
		{"8.8.8.8", "node-c"},
		{"192.168.1.1", "node-c"},
	}
	for _, tt := range tests {
		got := tbl.Lookup(net.ParseIP(tt.ip))
		if got != tt.want {
			t.Errorf("Lookup(%s) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

func TestExitRouteAddRemove(t *testing.T) {
	tbl := node.NewExitRouteTable("/dev/null")
	tbl.Add("10.0.0.0/8", "node-a")

	snap := tbl.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 route, got %d", len(snap))
	}

	tbl.Add("10.0.0.0/8", "node-b")
	snap = tbl.Snapshot()
	if len(snap) != 1 || snap[0].NodeID != "node-b" {
		t.Fatalf("upsert failed: %+v", snap)
	}

	tbl.Remove("10.0.0.0/8")
	if len(tbl.Snapshot()) != 0 {
		t.Fatal("expected 0 routes after remove")
	}
}

func TestSyncFromGossip(t *testing.T) {
	tbl := node.NewExitRouteTable("/dev/null")
	tbl.Add("192.168.0.0/16", "manual-node")

	tbl.SyncFromGossip([]node.PeerEntry{
		{NodeID: "exit1", ExitCIDRs: []string{"0.0.0.0/0"}},
		{NodeID: "exit2", ExitCIDRs: []string{"10.0.0.0/8"}},
	})

	snap := tbl.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(snap))
	}

	// Manual route preserved.
	for _, r := range snap {
		if r.CIDR == "192.168.0.0/16" && r.AutoLearn {
			t.Fatal("manual route should not be auto-learned")
		}
	}

	// Remove exit1.
	tbl.SyncFromGossip([]node.PeerEntry{
		{NodeID: "exit2", ExitCIDRs: []string{"10.0.0.0/8"}},
	})
	snap = tbl.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(snap))
	}
}
