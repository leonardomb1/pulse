package node

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const ringSize = 360 // 1 hour at 10-second intervals

// StatsSnapshot is one sample of per-peer metrics.
type StatsSnapshot struct {
	Timestamp   time.Time `json:"ts"`
	LatencyMS   float64   `json:"latency_ms"`
	LossRate    float64   `json:"loss_rate"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
	ActiveConns int       `json:"active_conns"`
}

// peerRing is a fixed-size circular buffer of stats snapshots for one peer.
type peerRing struct {
	data [ringSize]StatsSnapshot
	head int
	len  int
}

func (r *peerRing) record(s StatsSnapshot) {
	r.data[r.head] = s
	r.head = (r.head + 1) % ringSize
	if r.len < ringSize {
		r.len++
	}
}

// get returns snapshots in chronological order (oldest first).
func (r *peerRing) get() []StatsSnapshot {
	out := make([]StatsSnapshot, r.len)
	start := (r.head - r.len + ringSize) % ringSize
	for i := 0; i < r.len; i++ {
		out[i] = r.data[(start+i)%ringSize]
	}
	return out
}

func (r *peerRing) latest() StatsSnapshot {
	if r.len == 0 {
		return StatsSnapshot{}
	}
	return r.data[(r.head-1+ringSize)%ringSize]
}

// StatsRing holds per-peer ring buffers for time-series metrics.
type StatsRing struct {
	mu    sync.RWMutex
	rings map[string]*peerRing
}

// NewStatsRing creates an empty stats ring.
func NewStatsRing() *StatsRing {
	return &StatsRing{rings: make(map[string]*peerRing)}
}

// Record adds a snapshot for a peer.
func (s *StatsRing) Record(nodeID string, snap StatsSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rings[nodeID]
	if !ok {
		r = &peerRing{}
		s.rings[nodeID] = r
	}
	r.record(snap)
}

// Get returns the time-series for a peer in chronological order.
func (s *StatsRing) Get(nodeID string) []StatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rings[nodeID]
	if !ok {
		return nil
	}
	return r.get()
}

// AllLatest returns the most recent snapshot per peer.
func (s *StatsRing) AllLatest() map[string]StatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]StatsSnapshot, len(s.rings))
	for id, r := range s.rings {
		if r.len > 0 {
			out[id] = r.latest()
		}
	}
	return out
}

// CumulativeStats is the persisted summary for a peer (survives restarts).
type CumulativeStats struct {
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
}

// SaveCumulative writes per-peer cumulative totals to a JSON file.
func (s *StatsRing) SaveCumulative(path string) error {
	s.mu.RLock()
	out := make(map[string]CumulativeStats, len(s.rings))
	for id, r := range s.rings {
		if r.len > 0 {
			latest := r.latest()
			out[id] = CumulativeStats{BytesIn: latest.BytesIn, BytesOut: latest.BytesOut}
		}
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadCumulative restores cumulative totals from a JSON file.
func (s *StatsRing) LoadCumulative(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var saved map[string]CumulativeStats
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, cs := range saved {
		r, ok := s.rings[id]
		if !ok {
			r = &peerRing{}
			s.rings[id] = r
		}
		r.record(StatsSnapshot{
			Timestamp: time.Now(),
			BytesIn:   cs.BytesIn,
			BytesOut:  cs.BytesOut,
		})
	}
	return nil
}
