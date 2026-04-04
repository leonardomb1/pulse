package node

// QUIC transport for pulse relay-to-relay links.
//
// Why QUIC over WebSocket+yamux:
//
//  1. No head-of-line blocking: QUIC streams are independent at the packet level.
//     A stalled RDP stream won't delay an SSH keypress on the same connection.
//
//  2. 0-RTT reconnection: after a network change (wifi → 4G), QUIC can resume
//     the session in one round-trip instead of TCP's 3-way handshake + TLS.
//
//  3. Built-in multiplexing: no yamux layer needed; streams are native.
//
//  4. Built-in TLS 1.3: no separate TLS handshake on top of the transport.
//
// Transport selection:
//   - Nodes advertise both QUIC (UDP :8443) and WebSocket (TCP :8443) endpoints.
//   - Dialer tries QUIC first (100ms timeout). Falls back to WebSocket if QUIC
//     is blocked (some corporate firewalls drop UDP 443).
//   - Once connected, the session type is transparent to the rest of the node.

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// quicSession wraps a *quic.Conn to implement the Session interface.
type quicSession struct {
	conn *quic.Conn
}

func (q *quicSession) Open() (net.Conn, error) {
	stream, err := q.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	return &quicStream{stream: stream, conn: q.conn}, nil
}

func (q *quicSession) Accept() (net.Conn, error) {
	stream, err := q.conn.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return &quicStream{stream: stream, conn: q.conn}, nil
}

func (q *quicSession) Close() error     { return q.conn.CloseWithError(0, "close") }
func (q *quicSession) IsClosed() bool   {
	select {
	case <-q.conn.Context().Done():
		return true
	default:
		return false
	}
}
func (q *quicSession) Transport() string { return "quic" }

// quicStream wraps a quic.Stream as a net.Conn.
type quicStream struct {
	stream *quic.Stream
	conn   *quic.Conn
}

func (s *quicStream) Read(p []byte) (int, error)  { return s.stream.Read(p) }
func (s *quicStream) Write(p []byte) (int, error) { return s.stream.Write(p) }
func (s *quicStream) Close() error                { return s.stream.Close() }
func (s *quicStream) SetDeadline(t time.Time) error      { return s.stream.SetDeadline(t) }
func (s *quicStream) SetReadDeadline(t time.Time) error  { return s.stream.SetReadDeadline(t) }
func (s *quicStream) SetWriteDeadline(t time.Time) error { return s.stream.SetWriteDeadline(t) }
func (s *quicStream) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *quicStream) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }

// listenQUIC starts a QUIC listener on the given address.
func listenQUIC(addr string, tlsCfg *tls.Config, onSession func(Session, string)) error {
	// QUIC requires ALPN to be set.
	qtls := tlsCfg.Clone()
	qtls.NextProtos = []string{"github.com/leonardomb1/pulse/1"}

	ln, err := quic.ListenAddr(addr, qtls, &quic.Config{
		MaxIncomingStreams:    4096,
		KeepAlivePeriod:      15 * time.Second,
		MaxIdleTimeout:       60 * time.Second,
		EnableDatagrams:      false,
	})
	if err != nil {
		return err
	}
	Infof("QUIC listener on %s", addr)

	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				Infof("QUIC accept: %v", err)
				return
			}
			session := &quicSession{conn: conn}
			go onSession(session, conn.RemoteAddr().String())
		}
	}()
	return nil
}

// dialQUIC attempts a QUIC connection with a short timeout.
// Returns nil if QUIC is unreachable (caller should fall back to WebSocket).
func dialQUIC(ctx context.Context, peerAddr string, tlsCfg *tls.Config) (Session, error) {
	qtls := tlsCfg.Clone()
	qtls.NextProtos = []string{"github.com/leonardomb1/pulse/1"}

	qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(qctx, peerAddr, qtls, &quic.Config{
		MaxIncomingStreams: 4096,
		KeepAlivePeriod:   15 * time.Second,
		MaxIdleTimeout:    60 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return &quicSession{conn: conn}, nil
}

// dialBestTransport tries QUIC first, falls back to WebSocket+yamux.
// This is transparent to the caller — both return a Session.
func dialBestTransport(ctx context.Context, peerAddr string, tlsCfg *tls.Config) (Session, error) {
	session, err := dialQUIC(ctx, peerAddr, tlsCfg)
	if err == nil {
		Infof("dialed %s via QUIC", peerAddr)
		return session, nil
	}
	Warnf("QUIC to %s failed (%v) — falling back to WebSocket", peerAddr, err)
	return dialPeer(ctx, peerAddr, tlsCfg, "/relay")
}

// connectBestTransport is like connectWithRetry but uses QUIC-first transport selection.
func connectBestTransport(ctx context.Context, peerAddr string, tlsCfg *tls.Config, onConnect func(Session)) {
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		session, err := dialBestTransport(ctx, peerAddr, tlsCfg)
		if err != nil {
			Warnf("connect %s failed: %v — retrying in %s", peerAddr, err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}

		backoff = time.Second
		onConnect(session)

		for !session.IsClosed() {
			time.Sleep(500 * time.Millisecond)
		}
		Warnf("lost connection to %s — reconnecting", peerAddr)
	}
}
