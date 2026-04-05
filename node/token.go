package node

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// JoinToken is a scribe-managed token that authorizes nodes to join the mesh.
type JoinToken struct {
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // zero = no expiry
	MaxUses   int       `json:"max_uses,omitempty"`   // 0 = unlimited
	UseCount  int       `json:"use_count"`
}

// IsExpired reports whether the token has passed its expiry time.
func (t *JoinToken) IsExpired() bool {
	return !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt)
}

// IsExhausted reports whether the token has reached its max use count.
func (t *JoinToken) IsExhausted() bool {
	return t.MaxUses > 0 && t.UseCount >= t.MaxUses
}

// IsValid reports whether the token can still be used.
func (t *JoinToken) IsValid() bool {
	return !t.IsExpired() && !t.IsExhausted()
}

// GenerateToken creates a new random join token.
func GenerateToken(ttl time.Duration, maxUses int) JoinToken {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	t := JoinToken{
		Value:     hex.EncodeToString(b),
		CreatedAt: time.Now(),
		MaxUses:   maxUses,
	}
	if ttl > 0 {
		t.ExpiresAt = time.Now().Add(ttl)
	}
	return t
}
