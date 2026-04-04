package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/leonardomb1/pulse/node"
	"testing"
)

func TestSignVerifyNetConfig(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	cfg := node.NetworkConfig{
		Version:    12345,
		RevokedIDs: []string{"revoked1"},
		DNSZones:   []node.DNSZone{{Name: "test.pulse", Type: "A", Value: "10.0.0.1"}},
	}

	snc, err := node.SignNetConfig(cfg, priv, "scribe1")
	if err != nil {
		t.Fatalf("SignNetConfig: %v", err)
	}

	if err := node.VerifyNetConfig(snc, pub); err != nil {
		t.Fatalf("VerifyNetConfig should pass: %v", err)
	}

	// Wrong key should fail.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := node.VerifyNetConfig(snc, otherPub); err == nil {
		t.Fatal("VerifyNetConfig should fail with wrong key")
	}

	// Tampered config should fail.
	snc.Config.Version = 99999
	if err := node.VerifyNetConfig(snc, pub); err == nil {
		t.Fatal("VerifyNetConfig should fail with tampered config")
	}
}
