package tests

import (
	"os"
	"path/filepath"
	"pulse/node"
	"testing"
)

func TestLoadOrCreateIdentity(t *testing.T) {
	dir := t.TempDir()

	// First call creates identity.
	id1, err := node.LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id1.NodeID == "" {
		t.Fatal("empty nodeID")
	}
	if len(id1.PublicKey) == 0 || len(id1.PrivateKey) == 0 {
		t.Fatal("empty keys")
	}
	if id1.Joined {
		t.Fatal("should not be joined yet")
	}

	// Files should exist.
	for _, f := range []string{"identity.key", "identity.crt"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing file: %s", f)
		}
	}

	// Second call loads existing.
	id2, err := node.LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if id2.NodeID != id1.NodeID {
		t.Errorf("nodeID changed: %s -> %s", id1.NodeID, id2.NodeID)
	}
}

func TestStoreJoinResult(t *testing.T) {
	dir := t.TempDir()

	// Create identity first.
	node.LoadOrCreateIdentity(dir)

	// Simulate a join response.
	resp := node.JoinResponse{
		CACert:     "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
		SignedCert: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
		NodeID:     "test",
	}
	if err := node.StoreJoinResult(dir, resp); err != nil {
		t.Fatalf("StoreJoinResult: %v", err)
	}

	// ca.crt and identity.crt should be overwritten.
	caCert, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if string(caCert) != resp.CACert {
		t.Error("ca.crt not written")
	}
	idCert, _ := os.ReadFile(filepath.Join(dir, "identity.crt"))
	if string(idCert) != resp.SignedCert {
		t.Error("identity.crt not written")
	}
}

func TestFullJoinCycle(t *testing.T) {
	// Create CA and node in separate dirs, do full sign cycle.
	caDir := t.TempDir()
	nodeDir := t.TempDir()

	ca, err := node.InitCA(filepath.Join(caDir, "ca"), "tok")
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	id, err := node.LoadOrCreateIdentity(nodeDir)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if id.Joined {
		t.Fatal("should not be joined")
	}

	// Sign via CA.
	resp := ca.HandleJoin(node.JoinRequest{PublicKey: id.PublicKey, Token: "tok"})
	if resp.Error != "" {
		t.Fatalf("HandleJoin: %s", resp.Error)
	}

	// Store result.
	node.StoreJoinResult(nodeDir, resp)

	// Reload — should now be joined.
	id2, _ := node.LoadOrCreateIdentity(nodeDir)
	if !id2.Joined {
		t.Fatal("should be joined after storing CA cert")
	}
	if id2.CAPool == nil {
		t.Fatal("CAPool should be set")
	}
	if id2.NodeID != id.NodeID {
		t.Fatal("nodeID should not change after join")
	}
}
