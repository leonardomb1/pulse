package node

import (
	"fmt"
	"math"
)

// Router resolves a destination NodeID to the best Session via measured link quality.
//
// Scoring formula (lower = better):
//
//	score = latency_ms × (1 + loss_penalty × loss_rate) × (1 + hop_penalty × hop_count)
//
// This means:
//   - A 2-hop path at 5ms beats a 1-hop path at 200ms
//   - A lossy link is penalised even if it's fast (retransmits add latency anyway)
//   - Direct links (hop=0) get a natural advantage but aren't blindly preferred
//
// This is the Cloudflare Argo approach: route by measured quality, not topology.
const (
	lossPenalty = 5.0 // loss_rate multiplier — a 20% loss link costs 2× in score
	hopPenalty  = 0.3 // per-hop multiplier — each extra hop adds 30% to the score
)

type Router struct {
	table    *Table
	registry *LinkRegistry
}

func NewRouter(table *Table, registry *LinkRegistry) *Router {
	return &Router{table: table, registry: registry}
}

// Resolve returns the best Session for reaching destNodeID.
// When multiple viable paths exist, a MultipathSession is returned so streams
// are load-balanced across all of them (Cloudflare Argo-style multipath).
func (r *Router) Resolve(destNodeID string) (Session, error) {
	// Check we know about the destination at all.
	if _, ok := r.table.Get(destNodeID); !ok {
		return nil, fmt.Errorf("no route to node %s", destNodeID)
	}

	type candidate struct {
		session Session
		score   float64
	}

	var candidates []candidate

	// Direct link to the destination node itself.
	if link, ok := r.registry.Get(destNodeID); ok && !link.IsClosed() {
		entry, _ := r.table.Get(destNodeID)
		candidates = append(candidates, candidate{link.session, LinkScore(entry)})
	}

	// Relay paths: live peers that can forward to the destination.
	// Score each candidate as cost-to-peer + estimated onward cost, where the
	// onward cost is approximated from the destination's HopCount in the gossip
	// table (each hop was incremented as the entry propagated, so a higher
	// HopCount means more relays between us and the destination).
	destEntry, _ := r.table.Get(destNodeID)
	for _, link := range r.registry.All() {
		if link.NodeID == destNodeID || link.IsClosed() {
			continue
		}
		peerEntry, ok := r.table.Get(link.NodeID)
		if !ok {
			continue
		}
		score := LinkScore(peerEntry)
		// Apply extra penalty proportional to how many hops remain to the
		// destination. This naturally prefers peers closer to the destination.
		if destEntry.HopCount > 1 {
			score *= (1 + hopPenalty*float64(destEntry.HopCount-1))
		}
		candidates = append(candidates, candidate{link.session, score})
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no live peer to route through for node %s", destNodeID)
	}
	if len(candidates) == 1 {
		return candidates[0].session, nil
	}

	// Multiple paths — find the best score and include all paths within 2× of it.
	// Paths outside this band are too degraded to be worth using.
	bestScore := math.MaxFloat64
	for _, c := range candidates {
		if c.score < bestScore {
			bestScore = c.score
		}
	}
	var viable []Session
	var scores []float64
	for _, c := range candidates {
		if c.score <= bestScore*2 {
			viable = append(viable, c.session)
			scores = append(scores, c.score)
		}
	}
	if len(viable) == 1 {
		return viable[0], nil
	}
	return NewMultipathSession(viable, scores), nil
}

// LinkScore computes a composite routing score for a peer entry.
// Lower score = better path. Uses latency, loss rate, and hop count.
func LinkScore(e PeerEntry) float64 {
	latency := e.LatencyMS
	if latency <= 0 || math.IsInf(latency, 0) || math.IsNaN(latency) {
		// No measurement yet — assume a high but finite latency so the
		// link is still usable but deprioritised against measured ones.
		latency = 500.0
	}

	lossFactor := 1 + lossPenalty*e.LossRate
	hopFactor := 1 + hopPenalty*float64(e.HopCount)

	return latency * lossFactor * hopFactor
}
