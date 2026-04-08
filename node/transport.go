package node

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// wsConn wraps a websocket.Conn as a net.Conn for yamux.
type wsConn struct {
	conn   *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	reader io.Reader
	mu     sync.Mutex
}

func newWSConn(ctx context.Context, conn *websocket.Conn) *wsConn {
	ctx, cancel := context.WithCancel(ctx)
	return &wsConn{conn: conn, ctx: ctx, cancel: cancel}
}

func (w *wsConn) Read(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		if w.reader != nil {
			n, err := w.reader.Read(p)
			if err == io.EOF {
				w.reader = nil
				continue
			}
			return n, err
		}
		_, r, err := w.conn.Reader(w.ctx)
		if err != nil {
			return 0, err
		}
		w.reader = r
	}
}

func (w *wsConn) Write(p []byte) (int, error) {
	err := w.conn.Write(w.ctx, websocket.MessageBinary, p)
	return len(p), err
}

func (w *wsConn) Close() error {
	w.cancel()
	return w.conn.CloseNow()
}

func (w *wsConn) LocalAddr() net.Addr                { return wsAddr("ws-local") }
func (w *wsConn) RemoteAddr() net.Addr               { return wsAddr("ws-remote") }
func (w *wsConn) SetDeadline(t time.Time) error      { return nil }
func (w *wsConn) SetReadDeadline(t time.Time) error  { return nil }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return nil }

type wsAddr string

func (a wsAddr) Network() string { return "websocket" }
func (a wsAddr) String() string  { return string(a) }

// LinkRegistry manages active peer sessions.
type LinkRegistry struct {
	mu    sync.RWMutex
	links map[string]*PeerLink
}

func NewLinkRegistry() *LinkRegistry {
	return &LinkRegistry{links: make(map[string]*PeerLink)}
}

func (r *LinkRegistry) Add(link *PeerLink) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.links[link.NodeID] = link
}

func (r *LinkRegistry) Remove(nodeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.links, nodeID)
}

func (r *LinkRegistry) Get(nodeID string) (*PeerLink, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	l, ok := r.links[nodeID]
	return l, ok
}

func (r *LinkRegistry) All() []*PeerLink {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*PeerLink, 0, len(r.links))
	for _, l := range r.links {
		out = append(out, l)
	}
	return out
}

func (r *LinkRegistry) Has(nodeID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.links[nodeID]
	return ok
}

// SessionOwner returns the NodeID of the peer that owns the given session.
func (r *LinkRegistry) SessionOwner(s Session) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, l := range r.links {
		if l.session == s {
			return l.NodeID
		}
	}
	return ""
}

// reusePortListen creates a TCP listener. On Linux it sets SO_REUSEPORT
// so the kernel load-balances across multiple goroutines.
func reusePortListen(network, addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: setSocketOpts}
	return lc.Listen(context.Background(), network, addr)
}

// setTCPOpts applies TCP_NODELAY and keepalive to a TCPConn.
// TCP_NODELAY is critical for interactive protocols (SSH, RDP) — disables
// Nagle's algorithm which would batch small writes and add up to 200ms latency.
func setTCPOpts(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(30 * time.Second)
}

// dialPeer dials a peer relay over WSS and returns a Session.
// endpoint: "/relay" for normal relay connections, "/join" for bootstrapping.
func dialPeer(ctx context.Context, peerAddr string, tlsCfg *tls.Config, endpoint string) (Session, error) {
	wsURL := "wss://" + peerAddr + endpoint
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
				// TCP_NODELAY on the underlying TCP connection to the peer.
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					d := &net.Dialer{}
					c, err := d.DialContext(ctx, network, addr)
					if err != nil {
						return nil, err
					}
					setTCPOpts(c)
					return c, nil
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	wsc := newWSConn(ctx, conn)
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 15 * time.Second
	cfg.StreamCloseTimeout = 10 * time.Second
	// Use a larger window for high-bandwidth streams (RDP, file transfer).
	cfg.MaxStreamWindowSize = 256 * 1024

	session, err := yamux.Client(wsc, cfg)
	if err != nil {
		_ = wsc.Close()
		return nil, err
	}
	return newYamuxSession(session), nil
}

// serveWebSocket handles an inbound WebSocket upgrade and wraps it as a yamux server Session.
func serveWebSocket(ctx context.Context, w http.ResponseWriter, r *http.Request, onSession func(Session, string)) { //nolint:unparam
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}

	wsc := newWSConn(ctx, conn)
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 15 * time.Second
	cfg.MaxStreamWindowSize = 256 * 1024

	session, err := yamux.Server(wsc, cfg)
	if err != nil {
		_ = wsc.Close()
		return
	}

	onSession(newYamuxSession(session), r.RemoteAddr)
}
