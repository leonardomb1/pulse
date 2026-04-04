package tests

import (
	"pulse/node"
	"testing"
	"time"
)

func TestGenerateToken(t *testing.T) {
	tok := node.GenerateToken(1*time.Hour, 5)

	if len(tok.Value) != 64 {
		t.Fatalf("expected 64-char hex token, got %d chars", len(tok.Value))
	}
	if tok.MaxUses != 5 {
		t.Fatalf("expected MaxUses=5, got %d", tok.MaxUses)
	}
	if tok.ExpiresAt.IsZero() {
		t.Fatal("expected non-zero ExpiresAt with TTL")
	}
	if !tok.IsValid() {
		t.Fatal("fresh token should be valid")
	}
}

func TestTokenExpiry(t *testing.T) {
	tok := node.JoinToken{Value: "test", ExpiresAt: time.Now().Add(-1 * time.Second)}
	if !tok.IsExpired() {
		t.Fatal("should be expired")
	}
	if tok.IsValid() {
		t.Fatal("expired token should not be valid")
	}

	tok2 := node.JoinToken{Value: "test"}
	if tok2.IsExpired() {
		t.Fatal("no-expiry token should not be expired")
	}
}

func TestTokenMaxUses(t *testing.T) {
	tok := node.JoinToken{Value: "test", MaxUses: 2, UseCount: 0}
	if tok.IsExhausted() {
		t.Fatal("0/2 should not be exhausted")
	}

	tok.UseCount = 2
	if !tok.IsExhausted() {
		t.Fatal("2/2 should be exhausted")
	}
	if tok.IsValid() {
		t.Fatal("exhausted token should not be valid")
	}

	tok2 := node.JoinToken{Value: "test", MaxUses: 0, UseCount: 999}
	if tok2.IsExhausted() {
		t.Fatal("unlimited token should never be exhausted")
	}
}
