package node

// NAT hole punching — direct peer-to-peer QUIC connections bypassing the relay.
//
// How it works:
//
//  1. Public endpoint discovery:
//     Each node calls /whoami on a relay to learn its public IP:port.
//     This is stored in the gossip table (PeerEntry.PublicAddr).
//
//  2. Coordination (ack-based):
//     Node A wants a direct link to Node B.
//     A sends a "punch_start" message to B via the relay mesh containing
//     A's public addr and a random token.
//     B receives it and replies with "punch_ready" (B's public addr).
//     This round-trip guarantees both sides are active before probing begins.
//
//  3. Repeated UDP probing:
//     Once both sides are ready, they send QUIC dial attempts to each other's
//     public addr at 50ms intervals over a 3-second window. This opens the
//     NAT mapping on both sides. The first successful handshake wins.
//
//  4. Session upgrade:
//     The first successful QUIC handshake is registered in the LinkRegistry,
//     replacing the relay-routed path. Relay session remains as a fallback.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	punchInterval    = 30 * time.Second
	punchProbeWindow = 3 * time.Second       // how long to send probe dials
	punchProbeRate   = 50 * time.Millisecond // interval between probe attempts
	punchAckTimeout  = 5 * time.Second       // how long to wait for punch_ready reply
	punchDialTimeout = 2 * time.Second       // per-attempt QUIC dial timeout
)

// NATManager discovers the local public address and orchestrates hole punching
// to build direct links between peers.
type NATManager struct {
	selfID    string
	table     *Table
	registry  *LinkRegistry
	router    *Router
	tlsCfg    *tls.Config
	onSession func(ctx context.Context, session Session, hint, callerID string)
	onEvent   func(EventEntry)

	mu         sync.Mutex
	publicAddr string              // discovered public IP:port
	inProgress map[string]struct{} // nodeIDs currently being punched
}

func NewNATManager(selfID string, table *Table, registry *LinkRegistry, router *Router, tlsCfg *tls.Config, onSession func(context.Context, Session, string, string)) *NATManager {
	return &NATManager{
		selfID:     selfID,
		table:      table,
		registry:   registry,
		router:     router,
		tlsCfg:     tlsCfg,
		onSession:  onSession,
		inProgress: make(map[string]struct{}),
	}
}

// Run starts the periodic hole-punch loop.
func (m *NATManager) Run(ctx context.Context) {
	// Discover our public address from the first available bootstrap peer.
	go m.discoverPublicAddr(ctx)

	ticker := time.NewTicker(punchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.punchAll(ctx)
		}
	}
}

// discoverPublicAddr hits a relay's /whoami endpoint to learn our external IP.
func (m *NATManager) discoverPublicAddr(ctx context.Context) {
	// Wait for at least one peer to be available.
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}

		peers := m.registry.All()
		if len(peers) == 0 {
			continue
		}

		for _, peer := range peers {
			entry, ok := m.table.Get(peer.NodeID)
			if !ok || entry.Addr == "" {
				continue
			}

			addr, err := m.whoami(ctx, entry.Addr)
			if err != nil {
				continue
			}

			m.mu.Lock()
			m.publicAddr = addr
			m.mu.Unlock()

			// Advertise our public address in the gossip table.
			if self, ok := m.table.Get(m.selfID); ok {
				self.PublicAddr = addr
				self.LastSeen = time.Now()
				m.table.Upsert(self)
			}

			Debugf("NAT: public address discovered: %s", addr)
			return
		}
	}
}

// whoami calls the relay's /whoami endpoint and returns our observed public addr.
func (m *NATManager) whoami(ctx context.Context, relayAddr string) (string, error) {
	url := "https://" + relayAddr + "/whoami"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: m.tlsCfg},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	return string(body), err
}

// punchAll attempts hole punching to every peer without a direct session.
func (m *NATManager) punchAll(ctx context.Context) {
	entries := m.table.Snapshot()
	for _, entry := range entries {
		if entry.NodeID == m.selfID {
			continue
		}
		// Use PublicAddr (from /whoami) if available, otherwise fall back
		// to the gossip-announced Addr for LAN/direct-reachable peers.
		punchAddr := entry.PublicAddr
		if punchAddr == "" {
			punchAddr = entry.Addr
		}
		if punchAddr == "" {
			continue
		}
		if link, ok := m.registry.Get(entry.NodeID); ok && !link.IsClosed() {
			// Already have a direct link (or relay link).
			// Only try to upgrade if it's relay-mediated.
			if link.Transport() == "quic" {
				continue // already direct QUIC
			}
		}

		m.mu.Lock()
		if _, pending := m.inProgress[entry.NodeID]; pending {
			m.mu.Unlock()
			continue
		}
		m.inProgress[entry.NodeID] = struct{}{}
		m.mu.Unlock()

		go func(e PeerEntry, addr string) {
			defer func() {
				m.mu.Lock()
				delete(m.inProgress, e.NodeID)
				m.mu.Unlock()
			}()
			m.punchPeer(ctx, e, addr)
		}(entry, punchAddr)
	}
}

// punchPeer sends a punch_start to the peer and waits for punch_ready before probing.
// targetAddr is the address to probe (PublicAddr or Addr fallback).
func (m *NATManager) punchPeer(ctx context.Context, entry PeerEntry, targetAddr string) {
	// Determine our own address to send in the punch_start message.
	m.mu.Lock()
	myAddr := m.publicAddr
	m.mu.Unlock()
	if myAddr == "" {
		// Fall back to our gossip-announced address for LAN scenarios.
		if self, ok := m.table.Get(m.selfID); ok && self.Addr != "" {
			myAddr = self.Addr
		}
	}
	if myAddr == "" {
		return
	}

	token := randomToken()

	// Send punch_start to peer via relay and wait for punch_ready ack.
	session, err := m.router.Resolve(entry.NodeID)
	if err != nil {
		return
	}
	conn, err := session.Open()
	if err != nil {
		return
	}

	msg, _ := marshalStreamMsg(streamMsg{
		Type:        "punch_start",
		PunchNodeID: m.selfID,
		PunchAddr:   myAddr,
		PunchToken:  token,
	})
	_, _ = conn.Write(msg)

	// Wait for punch_ready response on the same stream.
	_ = conn.SetReadDeadline(time.Now().Add(punchAckTimeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	conn.Close()
	if err != nil || n == 0 {
		Debugf("NAT punch to %s: no ack received", entry.NodeID)
		return
	}

	var reply streamMsg
	if err := json.Unmarshal(buf[:n], &reply); err != nil || reply.Type != "punch_ready" {
		Debugf("NAT punch to %s: invalid ack", entry.NodeID)
		return
	}

	// Both sides are now ready. Begin probing.
	Debugf("NAT punch to %s: ack received, starting probe window", entry.NodeID)
	directSession, err := m.probeWindow(ctx, targetAddr)
	if err != nil {
		Warnf("NAT punch to %s failed: %v", entry.NodeID, err)
		m.emitEvent(EventEntry{Type: EventNATPunchFail, NodeID: entry.NodeID, Error: err.Error()})
		return
	}

	link := newNATPeerLink(entry.NodeID, directSession)
	m.registry.Add(link)
	Debugf("NAT punch success: direct QUIC link to %s (%s)", entry.NodeID, entry.PublicAddr)
	m.emitEvent(EventEntry{Type: EventNATPunchSuccess, NodeID: entry.NodeID, Detail: targetAddr})
	if m.onSession != nil {
		go m.onSession(ctx, directSession, entry.PublicAddr, entry.NodeID)
	}
}

// HandlePunchStart is called when we receive a "punch_start" stream from a peer.
// We reply with "punch_ready" on the same stream, then begin probing.
func (m *NATManager) HandlePunchStart(ctx context.Context, conn interface{ Write([]byte) (int, error) }, peerNodeID, peerPublicAddr, token string) {
	m.mu.Lock()
	myPublic := m.publicAddr
	m.mu.Unlock()

	// Reply with punch_ready so the initiator knows we're active.
	reply, _ := marshalStreamMsg(streamMsg{
		Type:        "punch_ready",
		PunchNodeID: m.selfID,
		PunchAddr:   myPublic,
		PunchToken:  token,
	})
	_, _ = conn.Write(reply)

	// Begin probing the peer's public address.
	directSession, err := m.probeWindow(ctx, peerPublicAddr)
	if err != nil {
		Warnf("NAT punch respond to %s failed: %v", peerNodeID, err)
		m.emitEvent(EventEntry{Type: EventNATPunchFail, NodeID: peerNodeID, Error: err.Error()})
		return
	}

	link := newNATPeerLink(peerNodeID, directSession)
	m.registry.Add(link)
	Debugf("NAT punch respond success: direct QUIC link to %s", peerNodeID)
	m.emitEvent(EventEntry{Type: EventNATPunchSuccess, NodeID: peerNodeID, Detail: peerPublicAddr})
	if m.onSession != nil {
		go m.onSession(ctx, directSession, peerPublicAddr, peerNodeID)
	}
}

// probeWindow repeatedly attempts QUIC dials to addr at punchProbeRate intervals
// over a punchProbeWindow duration. Returns the first successful session.
func (m *NATManager) probeWindow(ctx context.Context, addr string) (Session, error) {
	ctx, cancel := context.WithTimeout(ctx, punchProbeWindow)
	defer cancel()

	type result struct {
		session Session
		err     error
	}

	// Channel to receive the first successful connection.
	won := make(chan result, 1)

	ticker := time.NewTicker(punchProbeRate)
	defer ticker.Stop()

	var wg sync.WaitGroup

	for {
		select {
		case <-ctx.Done():
			// Wait for in-flight dials to finish so we don't leak goroutines.
			wg.Wait()
			select {
			case r := <-won:
				return r.session, r.err
			default:
				return nil, ctx.Err()
			}
		case <-ticker.C:
			wg.Add(1)
			go func() {
				defer wg.Done()
				dialCtx, dialCancel := context.WithTimeout(ctx, punchDialTimeout)
				defer dialCancel()
				sess, err := dialQUIC(dialCtx, addr, m.tlsCfg)
				if err == nil {
					select {
					case won <- result{session: sess}:
						cancel() // stop further probes
					default:
						sess.Close() // another probe already won
					}
				}
			}()
		}
	}
}

func (m *NATManager) emitEvent(e EventEntry) {
	if m.onEvent != nil {
		m.onEvent(e)
	}
}

func randomToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func marshalStreamMsg(msg streamMsg) ([]byte, error) {
	b, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
