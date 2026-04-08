package node

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
)

// MultipathSession wraps multiple Sessions to the same logical destination
// and provides weighted load balancing across them.
//
// Open() uses inverse-score weighted random selection — better paths get
// proportionally more traffic. A 5ms path gets ~10x more streams than a
// 50ms path instead of an equal split.
//
// Accept() fans in from all underlying sessions via background goroutines.
type MultipathSession struct {
	sessions []Session
	counters []*atomic.Int64
	weights  []float64 // normalized inverse-score weights, sum=1.0

	once    sync.Once
	fanCh   chan net.Conn
	closeCh chan struct{}
}

func NewMultipathSession(sessions []Session, scores []float64) *MultipathSession {
	counters := make([]*atomic.Int64, len(sessions))
	for i := range counters {
		counters[i] = new(atomic.Int64)
	}

	// Compute weights as inverse of scores, normalized to sum=1.0.
	// Lower score = better path = higher weight.
	weights := make([]float64, len(scores))
	var totalInv float64
	for i, s := range scores {
		if s <= 0 {
			s = 1 // avoid division by zero
		}
		weights[i] = 1.0 / s
		totalInv += weights[i]
	}
	if totalInv > 0 {
		for i := range weights {
			weights[i] /= totalInv
		}
	}

	return &MultipathSession{
		sessions: sessions,
		counters: counters,
		weights:  weights,
		fanCh:    make(chan net.Conn, 32),
		closeCh:  make(chan struct{}),
	}
}

// Open picks a session using weighted random selection (better paths get more traffic).
func (m *MultipathSession) Open() (net.Conn, error) {
	// Weighted random selection.
	r := rand.Float64()
	cumulative := 0.0
	for i, w := range m.weights {
		cumulative += w
		if r <= cumulative && !m.sessions[i].IsClosed() {
			m.counters[i].Add(1)
			conn, err := m.sessions[i].Open()
			if err != nil {
				m.counters[i].Add(-1)
				break // fall through to fallback
			}
			idx := i
			return &countedConn{Conn: conn, onClose: func() { m.counters[idx].Add(-1) }}, nil
		}
	}

	// Fallback: pick any open session (handles closed sessions in weighted pick).
	for i, s := range m.sessions {
		if s.IsClosed() {
			continue
		}
		m.counters[i].Add(1)
		conn, err := s.Open()
		if err != nil {
			m.counters[i].Add(-1)
			continue
		}
		idx := i
		return &countedConn{Conn: conn, onClose: func() { m.counters[idx].Add(-1) }}, nil
	}
	return nil, fmt.Errorf("multipath: all sessions closed")
}

func (m *MultipathSession) Accept() (net.Conn, error) {
	m.once.Do(m.startFanIn)
	select {
	case conn, ok := <-m.fanCh:
		if !ok {
			return nil, fmt.Errorf("multipath: all sessions closed")
		}
		return conn, nil
	case <-m.closeCh:
		return nil, fmt.Errorf("multipath: closed")
	}
}

func (m *MultipathSession) startFanIn() {
	var wg sync.WaitGroup
	for _, s := range m.sessions {
		wg.Add(1)
		go func(sess Session) {
			defer wg.Done()
			for {
				conn, err := sess.Accept()
				if err != nil {
					return
				}
				select {
				case m.fanCh <- conn:
				case <-m.closeCh:
					_ = conn.Close()
					return
				}
			}
		}(s)
	}
	go func() { wg.Wait(); close(m.fanCh) }()
}

func (m *MultipathSession) Close() error {
	select {
	case <-m.closeCh:
	default:
		close(m.closeCh)
	}
	var lastErr error
	for _, s := range m.sessions {
		if err := s.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (m *MultipathSession) IsClosed() bool {
	for _, s := range m.sessions {
		if !s.IsClosed() {
			return false
		}
	}
	return true
}

func (m *MultipathSession) Transport() string {
	return fmt.Sprintf("multipath(%d)", len(m.sessions))
}

type countedConn struct {
	net.Conn
	onClose   func()
	closeOnce sync.Once
}

func (c *countedConn) Close() error {
	c.closeOnce.Do(c.onClose)
	return c.Conn.Close()
}
