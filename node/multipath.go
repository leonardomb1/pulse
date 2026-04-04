package node

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// MultipathSession wraps multiple Sessions to the same logical destination
// and provides connection-level load balancing across them.
//
// Open() picks the session with the fewest open streams — work spreads
// evenly across paths, so a slow or congested relay doesn't bottleneck
// all connections.
//
// Accept() fans in from all underlying sessions via a single background
// goroutine per MultipathSession. This avoids goroutine leaks that would
// occur if every Accept() call spawned per-session goroutines.
type MultipathSession struct {
	sessions []Session
	counters []*atomic.Int64 // open stream count per session

	// Fan-in for Accept().
	once    sync.Once
	fanCh   chan net.Conn
	closeCh chan struct{}
}

func NewMultipathSession(sessions []Session) *MultipathSession {
	counters := make([]*atomic.Int64, len(sessions))
	for i := range counters {
		counters[i] = new(atomic.Int64)
	}
	m := &MultipathSession{
		sessions: sessions,
		counters: counters,
		fanCh:    make(chan net.Conn, 32),
		closeCh:  make(chan struct{}),
	}
	return m
}

// Open picks the least-loaded live session and opens a stream on it.
func (m *MultipathSession) Open() (net.Conn, error) {
	best := -1
	var bestLoad int64 = 1<<62 - 1
	for i, s := range m.sessions {
		if s.IsClosed() {
			continue
		}
		load := m.counters[i].Load()
		if load < bestLoad {
			bestLoad = load
			best = i
		}
	}
	if best < 0 {
		return nil, fmt.Errorf("multipath: all sessions closed")
	}

	m.counters[best].Add(1)
	conn, err := m.sessions[best].Open()
	if err != nil {
		m.counters[best].Add(-1)
		return nil, err
	}
	idx := best
	return &countedConn{Conn: conn, onClose: func() { m.counters[idx].Add(-1) }}, nil
}

// Accept returns the next inbound stream from any of the underlying sessions.
// Starts the background fan-in goroutine on first call.
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

// startFanIn starts one goroutine per session, all feeding fanCh.
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
					conn.Close()
					return
				}
			}
		}(s)
	}
	go func() {
		wg.Wait()
		close(m.fanCh)
	}()
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

// countedConn wraps a net.Conn and calls onClose when Close() is called.
type countedConn struct {
	net.Conn
	onClose  func()
	closeOnce sync.Once
}

func (c *countedConn) Close() error {
	c.closeOnce.Do(c.onClose)
	return c.Conn.Close()
}
