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
//
// UDP socket auto-tuning:
//   - On startup, reads net.core.rmem_max / wmem_max from /proc/sys
//   - Sets socket buffers to the kernel maximum (no sysctl required)
//   - Enables GSO/GRO/ECN automatically via quic-go's OOBCapablePacketConn

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

// quicConfig returns the shared QUIC configuration with tuned windows.
func quicConfig() *quic.Config {
	return &quic.Config{
		MaxIncomingStreams:             4096,
		KeepAlivePeriod:                15 * time.Second,
		MaxIdleTimeout:                 60 * time.Second,
		Allow0RTT:                      true,
		InitialStreamReceiveWindow:     4 * 1024 * 1024,  // 4MB — fast ramp on high-BDP links
		MaxStreamReceiveWindow:         16 * 1024 * 1024, // 16MB — sustain throughput
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,  // 8MB — aggregate across streams
		MaxConnectionReceiveWindow:     32 * 1024 * 1024, // 32MB
	}
}

// quicSession wraps a *quic.Conn to implement the Session interface.
type quicSession struct {
	conn      *quic.Conn
	transport *quic.Transport // non-nil for dialed sessions; closed when session closes
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

func (q *quicSession) Close() error {
	err := q.conn.CloseWithError(0, "close")
	if q.transport != nil {
		_ = q.transport.Close()
	}
	return err
}
func (q *quicSession) IsClosed() bool {
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

func (s *quicStream) Read(p []byte) (int, error)         { return s.stream.Read(p) }
func (s *quicStream) Write(p []byte) (int, error)        { return s.stream.Write(p) }
func (s *quicStream) Close() error                       { return s.stream.Close() }
func (s *quicStream) SetDeadline(t time.Time) error      { return s.stream.SetDeadline(t) }
func (s *quicStream) SetReadDeadline(t time.Time) error  { return s.stream.SetReadDeadline(t) }
func (s *quicStream) SetWriteDeadline(t time.Time) error { return s.stream.SetWriteDeadline(t) }
func (s *quicStream) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *quicStream) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }

// newTunedUDPConn creates a UDP socket with buffers tuned to the kernel maximum.
// Reads rmem_max/wmem_max from /proc/sys and sets the socket accordingly.
// Falls back to quic-go's desired 7MB or the OS default if /proc is unavailable.
func newTunedUDPConn(addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	recvMax := readSysctl("net.core.rmem_max")
	sendMax := readSysctl("net.core.wmem_max")

	// Use the kernel max, capped at 26MB (no point going higher).
	const cap = 26 * 1024 * 1024
	if recvMax > cap {
		recvMax = cap
	}
	if sendMax > cap {
		sendMax = cap
	}

	if recvMax > 0 {
		_ = conn.SetReadBuffer(recvMax)
	}
	if sendMax > 0 {
		_ = conn.SetWriteBuffer(sendMax)
	}

	Debugf("quic: UDP socket on %s (recv_buf=%dKB, send_buf=%dKB)",
		addr, recvMax/1024, sendMax/1024)

	return conn, nil
}

// readSysctl reads an integer sysctl value from /proc/sys.
// Returns 0 if unavailable.
func readSysctl(name string) int {
	path := "/proc/sys/" + strings.ReplaceAll(name, ".", "/")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return v
}

// listenQUIC starts a QUIC listener on the given address using a Transport
// with an auto-tuned UDP socket.
func listenQUIC(addr string, tlsCfg *tls.Config, onSession func(Session, string)) error {
	qtls := tlsCfg.Clone()
	qtls.NextProtos = []string{"github.com/leonardomb1/pulse/1"}

	conn, err := newTunedUDPConn(addr)
	if err != nil {
		return err
	}

	tr := &quic.Transport{
		Conn: conn,
	}

	ln, err := tr.Listen(qtls, quicConfig())
	if err != nil {
		_ = conn.Close()
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

	udpAddr, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, err
	}

	// Dial with an ephemeral local socket, also auto-tuned.
	conn, err := newTunedUDPConn(":0")
	if err != nil {
		return nil, err
	}

	tr := &quic.Transport{
		Conn: conn,
	}

	qconn, err := tr.Dial(qctx, udpAddr, qtls, quicConfig())
	if err != nil {
		_ = tr.Close()
		return nil, err
	}
	return &quicSession{conn: qconn, transport: tr}, nil
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

		// Wait for session to close efficiently (no polling).
		// QUIC sessions use context cancellation; yamux we poll as fallback.
		if qs, ok := session.(*quicSession); ok {
			<-qs.conn.Context().Done()
		} else {
			for !session.IsClosed() {
				time.Sleep(500 * time.Millisecond)
			}
		}
		Warnf("lost connection to %s — reconnecting", peerAddr)
	}
}
