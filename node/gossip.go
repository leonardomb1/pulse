package node

import (
	"context"
	"sync"
	"time"
)

const (
	maxHopCount   = 16
	peerStaleTTL  = 5 * time.Minute  // evict peers not seen within this window
	pruneInterval = 30 * time.Second // how often to sweep for stale entries
)

// PeerEntry is a routing table record that is gossipped between nodes.
type PeerEntry struct {
	NodeID    string    `json:"node_id"`
	Addr      string    `json:"addr"`
	PublicKey []byte    `json:"public_key"`
	LastSeen  time.Time `json:"last_seen"`
	HopCount  int       `json:"hop_count"`
	IsCA      bool      `json:"is_ca,omitempty"`

	// Measured link quality — populated by the Prober, not gossipped.
	LatencyMS float64 `json:"latency_ms,omitempty"`
	LossRate  float64 `json:"loss_rate,omitempty"`

	// NAT hole punching.
	PublicAddr string `json:"public_addr,omitempty"`

	// Exit node routing.
	IsExit    bool     `json:"is_exit,omitempty"`
	ExitCIDRs []string `json:"exit_cidrs,omitempty"`

	// Service discovery (DNS SRV records).
	Services []ServiceRecord `json:"services,omitempty"`

	// ACL policy for this node, distributed by the CA via gossip.
	ACL *NodeACL `json:"acl,omitempty"`

	// Scribe role — collects stats and distributes NetworkConfig.
	IsScribe      bool   `json:"is_scribe,omitempty"`
	ScribeAPIAddr string `json:"scribe_api_addr,omitempty"` // HTTP API address of scribe

	// Tun device — mesh IP assigned to this node.
	MeshIP string `json:"mesh_ip,omitempty"`

	// Operator-assigned metadata (populated from NetworkConfig, not gossipped).
	Name string   `json:"name,omitempty"`
	Tags []string `json:"tags,omitempty"`
}

// Table is a thread-safe routing table.
type Table struct {
	mu      sync.RWMutex
	entries map[string]PeerEntry // keyed by NodeID
}

func NewTable() *Table {
	return &Table{entries: make(map[string]PeerEntry)}
}

// Upsert adds or updates an entry, keeping the freshest LastSeen and lowest HopCount.
func (t *Table) Upsert(e PeerEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e.HopCount > maxHopCount {
		return
	}
	existing, ok := t.entries[e.NodeID]
	if !ok || e.LastSeen.After(existing.LastSeen) || e.HopCount < existing.HopCount {
		t.entries[e.NodeID] = e
	}
}

// UpsertForce unconditionally replaces an entry, bypassing staleness checks.
// Use only for the local self-entry where we always want the current state to win.
func (t *Table) UpsertForce(e PeerEntry) {
	if e.HopCount > maxHopCount {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[e.NodeID] = e
}

// ExitNodes returns all entries advertising themselves as exit nodes.
func (t *Table) ExitNodes() []PeerEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []PeerEntry
	for _, e := range t.entries {
		if e.IsExit {
			out = append(out, e)
		}
	}
	return out
}

// FindScribe returns the routing entry of the Scribe node, if known.
func (t *Table) FindScribe() (PeerEntry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, e := range t.entries {
		if e.IsScribe {
			return e, true
		}
	}
	return PeerEntry{}, false
}

// FindCA returns the routing entry of the CA node, if known.
func (t *Table) FindCA() (PeerEntry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, e := range t.entries {
		if e.IsCA {
			return e, true
		}
	}
	return PeerEntry{}, false
}

// Snapshot returns a copy of all entries.
func (t *Table) Snapshot() []PeerEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]PeerEntry, 0, len(t.entries))
	for _, e := range t.entries {
		out = append(out, e)
	}
	return out
}

// Get returns a single entry by NodeID.
func (t *Table) Get(nodeID string) (PeerEntry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.entries[nodeID]
	return e, ok
}

// MergeFrom merges received entries, incrementing HopCount by 1.
func (t *Table) MergeFrom(entries []PeerEntry, selfID string) {
	for _, e := range entries {
		if e.NodeID == selfID {
			continue // don't overwrite our own entry
		}
		e.HopCount++
		t.Upsert(e)
	}
}

// PruneStale removes entries whose LastSeen is older than peerStaleTTL.
// selfID is never pruned — the self-entry is refreshed continuously.
func (t *Table) PruneStale(selfID string) {
	cutoff := time.Now().Add(-peerStaleTTL)
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, e := range t.entries {
		if id != selfID && e.LastSeen.Before(cutoff) {
			delete(t.entries, id)
		}
	}
}

// RunPruner starts a background goroutine that periodically evicts stale peers.
// It stops when ctx is cancelled.
func (t *Table) RunPruner(ctx context.Context, selfID string) {
	ticker := time.NewTicker(pruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.PruneStale(selfID)
		}
	}
}
