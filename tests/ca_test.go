package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/leonardomb1/pulse/node"
	"testing"
	"time"
)

func TestCAInitAndLoad(t *testing.T) {
	dir := t.TempDir()

	ca, err := node.InitCA(dir, "test-token")
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if ca.JoinToken != "test-token" {
		t.Errorf("JoinToken = %q", ca.JoinToken)
	}
	if ca.Cert == nil || ca.Pool == nil {
		t.Fatal("CA cert/pool not initialized")
	}

	// Load from disk.
	ca2, err := node.LoadCA(dir, "test-token")
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if ca2.Cert.Subject.CommonName != "pulse-ca" {
		t.Errorf("CA CN = %q", ca2.Cert.Subject.CommonName)
	}
}

func TestCAHandleJoin(t *testing.T) {
	dir := t.TempDir()
	ca, _ := node.InitCA(dir, "secret")

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	req := node.JoinRequest{PublicKey: pub, Token: "secret"}

	resp := ca.HandleJoin(req)
	if resp.Error != "" {
		t.Fatalf("HandleJoin: %s", resp.Error)
	}
	if resp.CACert == "" || resp.SignedCert == "" {
		t.Fatal("empty cert in response")
	}
	if resp.NodeID == "" {
		t.Fatal("empty node ID")
	}
}

func TestCAHandleJoinBadToken(t *testing.T) {
	dir := t.TempDir()
	ca, _ := node.InitCA(dir, "secret")

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	req := node.JoinRequest{PublicKey: pub, Token: "wrong"}

	resp := ca.HandleJoin(req)
	if resp.Error == "" {
		t.Fatal("should reject wrong token")
	}
}

func TestCAHandleJoinRevoked(t *testing.T) {
	dir := t.TempDir()
	ca, _ := node.InitCA(dir, "secret")

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	req := node.JoinRequest{PublicKey: pub, Token: "secret"}

	// First join succeeds.
	resp := ca.HandleJoin(req)
	if resp.Error != "" {
		t.Fatalf("first join: %s", resp.Error)
	}

	// Revoke the node.
	ca.RevokeNode(resp.NodeID)

	// Second join should fail.
	resp2 := ca.HandleJoin(req)
	if resp2.Error == "" {
		t.Fatal("should reject revoked node")
	}
}

func TestCATokenValidation(t *testing.T) {
	dir := t.TempDir()
	ca, _ := node.InitCA(dir, "master-token")

	// Sync scribe-managed tokens.
	ca.SyncTokens([]node.JoinToken{
		{Value: "scribe-token-1", ExpiresAt: time.Now().Add(1 * time.Hour), MaxUses: 1},
		{Value: "expired-token", ExpiresAt: time.Now().Add(-1 * time.Hour)},
	})

	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Scribe token should work.
	resp := ca.HandleJoin(node.JoinRequest{PublicKey: pub, Token: "scribe-token-1"})
	if resp.Error != "" {
		t.Fatalf("scribe token: %s", resp.Error)
	}

	// Generate new key for second join (same key = same nodeID, would conflict).
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	// Master token fallback should work.
	resp = ca.HandleJoin(node.JoinRequest{PublicKey: pub2, Token: "master-token"})
	if resp.Error != "" {
		t.Fatalf("master token: %s", resp.Error)
	}

	// Expired token should fail.
	pub3, _, _ := ed25519.GenerateKey(rand.Reader)
	resp = ca.HandleJoin(node.JoinRequest{PublicKey: pub3, Token: "expired-token"})
	if resp.Error == "" {
		t.Fatal("expired token should be rejected")
	}

	// Wrong token should fail.
	pub4, _, _ := ed25519.GenerateKey(rand.Reader)
	resp = ca.HandleJoin(node.JoinRequest{PublicKey: pub4, Token: "nope"})
	if resp.Error == "" {
		t.Fatal("wrong token should be rejected")
	}
}

func TestCASignIdentity(t *testing.T) {
	dir := t.TempDir()
	ca, _ := node.InitCA(dir, "tok")

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	resp, err := ca.SignIdentity(pub, "test-node-id")
	if err != nil {
		t.Fatalf("SignIdentity: %v", err)
	}
	if resp.NodeID != "test-node-id" {
		t.Errorf("nodeID = %q", resp.NodeID)
	}
	if resp.SignedCert == "" {
		t.Fatal("empty signed cert")
	}
}

func TestCARevocationSync(t *testing.T) {
	dir := t.TempDir()
	ca, _ := node.InitCA(dir, "tok")

	ca.SyncRevokedIDs([]string{"a", "b"})
	if !ca.IsRevoked("a") || !ca.IsRevoked("b") {
		t.Fatal("should be revoked")
	}
	if ca.IsRevoked("c") {
		t.Fatal("c should not be revoked")
	}
}
