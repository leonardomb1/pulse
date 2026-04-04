package node

// NAT hole punching — direct peer-to-peer QUIC connections bypassing the relay.
//
// How it works:
//
//  1. Public endpoint discovery:
//     Each node calls /whoami on a relay to learn its public IP:port.
//     This is stored in the gossip table (PeerEntry.PublicAddr).
//
//  2. Coordination:
//     Node A wants a direct link to Node B.
//     A sends a "punch" stream message to B via the relay mesh.
//     The message includes A's public addr and a shared random token,
//     plus a PunchAt timestamp so both sides punch simultaneously.
//
//  3. Simultaneous UDP punch:
//     Both A and B send QUIC Initial packets to each other's public addr
//     at the same instant. This opens the NAT mapping on both sides.
//
//  4. Session upgrade:
//     The first successful QUIC handshake wins. Both sides register the
//     direct session in the LinkRegistry, replacing the relay-routed path.
//     Relay session remains as a fallback.
//
// This is the mechanism that makes Tailscale feel like a LAN — the relay
// is only needed for signalling and fallback, not for data.

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
	punchInterval = 30 * time.Second
	punchTimeout  = 5 * time.Second
	punchLeadTime = 500 * time.Millisecond // how far ahead to schedule simultaneous punch
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
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: m.tlsCfg},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(url)
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
		if entry.NodeID == m.selfID || entry.PublicAddr == "" {
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

		go func(e PeerEntry) {
			defer func() {
				m.mu.Lock()
				delete(m.inProgress, e.NodeID)
				m.mu.Unlock()
			}()
			m.punchPeer(ctx, e)
		}(entry)
	}
}

// punchPeer sends a coordination message to the peer and attempts the punch.
func (m *NATManager) punchPeer(ctx context.Context, entry PeerEntry) {
	m.mu.Lock()
	myPublic := m.publicAddr
	m.mu.Unlock()
	if myPublic == "" {
		return
	}

	token := randomToken()
	punchAt := time.Now().Add(punchLeadTime)

	// Send coordination message to peer via relay.
	session, err := m.router.Resolve(entry.NodeID)
	if err != nil {
		return
	}
	conn, err := session.Open()
	if err != nil {
		return
	}

	msg, _ := marshalStreamMsg(streamMsg{
		Type:        "punch",
		PunchNodeID: m.selfID,
		PunchAddr:   myPublic,
		PunchToken:  token,
		PunchAt:     punchAt,
	})
	conn.Write(msg)
	conn.Close()

	// Wait until punchAt then attempt.
	time.Sleep(time.Until(punchAt))

	directSession, err := m.attemptDirectQUIC(ctx, entry.PublicAddr)
	if err != nil {
		Warnf("NAT punch to %s failed: %v", entry.NodeID, err)
		return
	}

	link := newPeerLink(entry.NodeID, directSession)
	m.registry.Add(link)
	Debugf("NAT punch success: direct QUIC link to %s (%s)", entry.NodeID, entry.PublicAddr)
	// Start the stream accept loop so the peer can open streams on this direct session.
	if m.onSession != nil {
		go m.onSession(ctx, directSession, entry.PublicAddr, entry.NodeID)
	}
}

// HandlePunchRequest is called when we receive a "punch" stream from a peer.
// We attempt to dial the peer's public address at the scheduled time.
func (m *NATManager) HandlePunchRequest(ctx context.Context, peerNodeID, peerPublicAddr, token string, punchAt time.Time) {
	time.Sleep(time.Until(punchAt))

	directSession, err := m.attemptDirectQUIC(ctx, peerPublicAddr)
	if err != nil {
		Warnf("NAT punch respond to %s failed: %v", peerNodeID, err)
		return
	}

	link := newPeerLink(peerNodeID, directSession)
	m.registry.Add(link)
	Debugf("NAT punch respond success: direct QUIC link to %s", peerNodeID)
	// Start the stream accept loop so the peer can open streams on this direct session.
	if m.onSession != nil {
		go m.onSession(ctx, directSession, peerPublicAddr, peerNodeID)
	}
}

// attemptDirectQUIC tries to establish a direct QUIC connection to addr.
func (m *NATManager) attemptDirectQUIC(ctx context.Context, addr string) (Session, error) {
	ctx, cancel := context.WithTimeout(ctx, punchTimeout)
	defer cancel()
	return dialQUIC(ctx, addr, m.tlsCfg)
}

func randomToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func marshalStreamMsg(msg streamMsg) ([]byte, error) {
	b, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
