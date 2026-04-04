package node

import (
	"net"

	"github.com/hashicorp/yamux"
)

// Session is an abstract multiplexed connection to a peer.
// Implemented by both yamuxSession (WebSocket) and quicSession (QUIC).
type Session interface {
	// Open creates a new outbound stream to the peer.
	Open() (net.Conn, error)
	// Accept waits for the peer to open an inbound stream.
	Accept() (net.Conn, error)
	// Close terminates the session and all its streams.
	Close() error
	// IsClosed reports whether the session has been terminated.
	IsClosed() bool
	// Transport returns a human-readable transport name for logging.
	Transport() string
}

// yamuxSession wraps a *yamux.Session.
type yamuxSession struct {
	s *yamux.Session
}

func newYamuxSession(s *yamux.Session) Session {
	return &yamuxSession{s: s}
}

func (y *yamuxSession) Open() (net.Conn, error)  { return y.s.Open() }
func (y *yamuxSession) Accept() (net.Conn, error) { return y.s.Accept() }
func (y *yamuxSession) Close() error              { return y.s.Close() }
func (y *yamuxSession) IsClosed() bool            { return y.s.IsClosed() }
func (y *yamuxSession) Transport() string         { return "websocket+yamux" }

// PeerLink is an active session to a peer node.
type PeerLink struct {
	NodeID  string
	session Session
}

func newPeerLink(nodeID string, s Session) *PeerLink {
	return &PeerLink{NodeID: nodeID, session: s}
}

func (p *PeerLink) Open() (net.Conn, error) { return p.session.Open() }
func (p *PeerLink) IsClosed() bool          { return p.session.IsClosed() }
func (p *PeerLink) Transport() string       { return p.session.Transport() }
func (p *PeerLink) Close() error            { return p.session.Close() }
