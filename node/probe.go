package node

// Prober implements masscan-inspired active link measurement.
//
// masscan's key insight applied here: don't probe peers one-by-one (O(n) time).
// Instead, fire probes to ALL peers simultaneously in separate goroutines,
// collect results concurrently, and update the routing table in one pass.
// Probe time is O(1) regardless of mesh size — limited only by the slowest peer.
//
// Each probe measures:
//   - RTT (round-trip time) to each directly connected peer
//   - Loss rate (rolling window of last N probes)
//
// The router uses these measurements to pick the lowest-latency path through
// the mesh, not just the fewest hops — same idea as Cloudflare Argo.

import (
	"bufio"
	"encoding/json"
	"math"
	"sync"
	"time"
)

const (
	probeInterval  = 5 * time.Second  // how often to probe all peers
	probeTimeout   = 3 * time.Second  // max wait for a pong
	probeWindowLen = 10               // rolling window for loss calculation
)

// LinkStats holds measured quality metrics for a single peer link.
type LinkStats struct {
	mu        sync.RWMutex
	rtts      []time.Duration // rolling window of recent RTTs
	successes []bool          // rolling window: true=success, false=loss
	idx       int             // next write position in the window
	filled    bool            // window has been filled at least once
}

func newLinkStats() *LinkStats {
	return &LinkStats{
		rtts:      make([]time.Duration, probeWindowLen),
		successes: make([]bool, probeWindowLen),
	}
}

func (s *LinkStats) record(rtt time.Duration, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rtts[s.idx] = rtt
	s.successes[s.idx] = success
	s.idx = (s.idx + 1) % probeWindowLen
	if s.idx == 0 {
		s.filled = true
	}
}

// LatencyMS returns the exponentially-weighted moving average RTT in milliseconds.
// Returns math.MaxFloat64 if no successful probes yet.
func (s *LinkStats) LatencyMS() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := probeWindowLen
	if !s.filled {
		limit = s.idx
	}
	if limit == 0 {
		return math.MaxFloat64
	}

	// EWMA with alpha=0.3 — recent samples weighted more heavily.
	const alpha = 0.3
	var ewma float64
	first := true
	for i := 0; i < limit; i++ {
		idx := (s.idx - limit + i + probeWindowLen) % probeWindowLen
		if !s.successes[idx] {
			continue
		}
		ms := float64(s.rtts[idx].Microseconds()) / 1000.0
		if first {
			ewma = ms
			first = false
		} else {
			ewma = alpha*ms + (1-alpha)*ewma
		}
	}
	if first {
		return math.MaxFloat64 // all probes in window failed
	}
	return ewma
}

// LossRate returns the fraction of failed probes in the rolling window (0.0–1.0).
func (s *LinkStats) LossRate() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := probeWindowLen
	if !s.filled {
		limit = s.idx
	}
	if limit == 0 {
		return 0
	}

	var losses int
	for i := 0; i < limit; i++ {
		idx := (s.idx - limit + i + probeWindowLen) % probeWindowLen
		if !s.successes[idx] {
			losses++
		}
	}
	return float64(losses) / float64(limit)
}

// Prober continuously measures link quality to all directly-connected peers.
type Prober struct {
	registry *LinkRegistry
	table    *Table

	mu    sync.RWMutex
	stats map[string]*LinkStats // nodeID → stats
}

func NewProber(registry *LinkRegistry, table *Table) *Prober {
	return &Prober{
		registry: registry,
		table:    table,
		stats:    make(map[string]*LinkStats),
	}
}

// Run starts the probe loop. Call in a goroutine.
func (p *Prober) Run(ctx interface{ Done() <-chan struct{} }) {
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.probeAll()
		}
	}
}

// probeAll fires probes to every connected peer simultaneously.
// This is the masscan insight: O(1) time regardless of mesh size.
func (p *Prober) probeAll() {
	peers := p.registry.All()
	if len(peers) == 0 {
		return
	}

	var wg sync.WaitGroup
	results := make(chan probeResult, len(peers))

	for _, link := range peers {
		if link.IsClosed() {
			continue
		}
		wg.Add(1)
		go func(l *PeerLink) {
			defer wg.Done()
			rtt, err := p.probePeer(l)
			results <- probeResult{nodeID: l.NodeID, rtt: rtt, ok: err == nil}
		}(link)
	}

	// Close results channel when all goroutines finish.
	go func() { wg.Wait(); close(results) }()

	// Collect and apply results — update routing table with fresh metrics.
	for r := range results {
		stats := p.statsFor(r.nodeID)
		stats.record(r.rtt, r.ok)

		latencyMS := stats.LatencyMS()
		lossRate := stats.LossRate()

		if entry, ok := p.table.Get(r.nodeID); ok {
			entry.LatencyMS = latencyMS
			entry.LossRate = lossRate
			p.table.Upsert(entry)
		}

		if !r.ok {
			Warnf("probe %s: timeout (loss=%.0f%%)", r.nodeID, lossRate*100)
		}
	}
}

type probeResult struct {
	nodeID string
	rtt    time.Duration
	ok     bool
}

// probePeer opens a stream, sends a probe, and waits for a pong.
func (p *Prober) probePeer(link *PeerLink) (time.Duration, error) {
	conn, err := link.Open()
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))

	sentAt := time.Now()
	msg, _ := json.Marshal(streamMsg{Type: "probe", SentAt: sentAt})
	if _, err := conn.Write(append(msg, '\n')); err != nil {
		return 0, err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}

	var reply streamMsg
	if err := json.Unmarshal([]byte(line), &reply); err != nil || reply.Type != "pong" {
		return 0, err
	}

	return time.Since(sentAt), nil
}

func (p *Prober) statsFor(nodeID string) *LinkStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok := p.stats[nodeID]; ok {
		return s
	}
	s := newLinkStats()
	p.stats[nodeID] = s
	return s
}

