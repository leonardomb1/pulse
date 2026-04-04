package tests

import (
	"path/filepath"
	"pulse/node"
	"testing"
	"time"
)

func TestAuditLogWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	al, err := node.OpenAuditLog(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer al.Close()

	// Write entries.
	al.Write(node.AuditEntry{Op: node.AuditJoinAttempted, NodeID: "node1"})
	al.Write(node.AuditEntry{Op: node.AuditCertIssued, NodeID: "node1"})
	al.Write(node.AuditEntry{Op: node.AuditJoinFailed, NodeID: "node2", Error: "bad token"})
	al.Write(node.AuditEntry{Op: node.AuditCertRevoked, NodeID: "node3"})

	// ReadAll.
	entries, err := al.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}

	// Verify timestamps are set.
	for _, e := range entries {
		if e.Timestamp.IsZero() {
			t.Error("timestamp should be auto-set")
		}
	}

	// ReadByNode.
	node1, _ := al.ReadByNode("node1")
	if len(node1) != 2 {
		t.Errorf("ReadByNode(node1): got %d, want 2", len(node1))
	}

	node2, _ := al.ReadByNode("node2")
	if len(node2) != 1 || node2[0].Error != "bad token" {
		t.Errorf("ReadByNode(node2): %+v", node2)
	}

	// ReadSince.
	recent, _ := al.ReadSince(time.Now().Add(-1 * time.Minute))
	if len(recent) != 4 {
		t.Errorf("ReadSince(1m ago): got %d, want 4", len(recent))
	}

	future, _ := al.ReadSince(time.Now().Add(1 * time.Hour))
	if len(future) != 0 {
		t.Errorf("ReadSince(future): got %d, want 0", len(future))
	}
}
