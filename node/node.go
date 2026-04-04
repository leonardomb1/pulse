package node

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"slices"
	"strings"
	"time"

	"github.com/leonardomb1/pulse/config"
)

// streamMsg is the first JSON line on every yamux/QUIC stream.
type streamMsg struct {
	Type string `json:"type"`

	// handshake
	NodeID        string `json:"node_id,omitempty"`
	NetworkID     string `json:"network_id,omitempty"`
	Addr          string `json:"addr,omitempty"`
	PublicKey     []byte `json:"public_key,omitempty"`
	IsCA          bool   `json:"is_ca,omitempty"`
	IsExit        bool   `json:"is_exit,omitempty"`
	IsScribe      bool   `json:"is_scribe,omitempty"`
	ScribeAPIAddr string `json:"scribe_api_addr,omitempty"`
	MeshIP        string `json:"mesh_ip,omitempty"`

	// gossip
	Entries []PeerEntry `json:"entries,omitempty"`
	ACLs    []NodeACL   `json:"acls,omitempty"`

	// tunnel
	DestNodeID string `json:"dest_node,omitempty"`
	DestAddr   string `json:"dest_addr,omitempty"`

	// join
	JoinReq  *JoinRequest  `json:"join_req,omitempty"`
	JoinResp *JoinResponse `json:"join_resp,omitempty"`

	// probe / pong
	SentAt time.Time `json:"sent_at,omitempty"`

	// NAT punch coordination
	PunchNodeID string    `json:"punch_node,omitempty"`
	PunchAddr   string    `json:"punch_addr,omitempty"`
	PunchToken  string    `json:"punch_token,omitempty"`
	PunchAt     time.Time `json:"punch_at,omitempty"`

	// network config (distributed by scribe)
	NetConfig *SignedNetConfig `json:"net_config,omitempty"`

	// stats (pushed by nodes to scribe)
	Stats *NodeStats `json:"stats,omitempty"`

	// revoke (forwarded to scribe over mesh)
	RevokeNodeID string `json:"revoke_node_id,omitempty"`
}

// authedConn wraps a net.Conn with the verified identity of the remote node
// and a reference to its parent session (needed to register in LinkRegistry).
type authedConn struct {
	net.Conn
	callerNodeID string
	session      Session // the multiplexed session this stream came from
}

// Node is a running relay instance.
type Node struct {
	id         string
	cfg        *config.Config
	identity   *Identity
	ca         *CA
	table      *Table
	registry   *LinkRegistry
	router     *Router
	prober     *Prober
	aclTable   *ACLTable
	exitRoutes *ExitRouteTable
	socks      *SOCKSServer
	dns        *DNSServer
	nat        *NATManager
	tun        TunDevice
	scribe     *Scribe
	netCfg     netConfigStore
	shutdown   chan struct{} // closed by Stop() to trigger graceful shutdown

	// Delta-gossip: track last-sent table version per peer.
	gossipVersionsMu sync.Mutex
	gossipVersions   map[string]uint64 // peerNodeID → last-sent version
	lastFullGossip   time.Time         // time of last full table push
}

func New(cfg *config.Config, ca *CA) (*Node, error) {
	identity, err := LoadOrCreateIdentity(cfg.Node.DataDir)
	if err != nil {
		return nil, err
	}

	table := NewTable()

	// Seed routing table from persisted peers (speeds up mesh convergence on restart).
	if cfg.Persist.Enabled {
		if saved, err := LoadPeers(cfg.Node.DataDir); err == nil && len(saved) > 0 {
			table.MergeFrom(saved, "") // HopCount+1; selfID="" so nothing is skipped
			Debugf("persist: loaded %d peers from disk", len(saved))
		}
	}

	registry := NewLinkRegistry()
	router := NewRouter(table, registry)
	aclTable := NewACLTable()

	exitRoutes := NewExitRouteTable(cfg.Exit.RoutesFile)
	exitRoutes.Load() // best-effort; no error if file missing

	isCA := ca != nil
	isExit := cfg.Exit.Enabled
	isScribe := cfg.Scribe.Enabled

	// CA node: sign its own identity cert on first start so peers can verify it
	// via mTLS. Without this, the CA presents a self-signed cert that joined nodes
	// (which verify against the CA pool) would reject.
	if isCA && !identity.Joined {
		resp, err := ca.SignIdentity(identity.PublicKey, identity.NodeID)
		if err != nil {
			return nil, fmt.Errorf("CA self-sign: %w", err)
		}
		if err := StoreJoinResult(cfg.Node.DataDir, resp); err != nil {
			return nil, fmt.Errorf("CA self-sign store: %w", err)
		}
		// Reload so identity.TLSCert and identity.CAPool reflect the CA-signed cert.
		identity, err = LoadOrCreateIdentity(cfg.Node.DataDir)
		if err != nil {
			return nil, fmt.Errorf("reload identity after CA self-sign: %w", err)
		}
	}

	n := &Node{
		id:         identity.NodeID,
		cfg:        cfg,
		identity:   identity,
		ca:         ca,
		table:      table,
		registry:   registry,
		router:     router,
		prober:     NewProber(registry, table),
		aclTable:   aclTable,
		exitRoutes: exitRoutes,
		shutdown:        make(chan struct{}),
		gossipVersions: make(map[string]uint64),
	}

	// Build the complete self-entry in one shot and force-write it.
	// Using UpsertForce avoids the equal-timestamp rejection in Upsert that would
	// silently drop role flags (IsScribe, IsExit, MeshIP) set after UpsertSelf.
	selfEntry := PeerEntry{
		NodeID:    identity.NodeID,
		Addr:      cfg.Node.Addr,
		PublicKey: identity.PublicKey,
		LastSeen:  time.Now(),
		HopCount:  0,
		IsCA:      isCA,
	}
	if isExit {
		selfEntry.IsExit = true
		selfEntry.ExitCIDRs = cfg.Exit.CIDRs
	}
	if isScribe {
		selfEntry.IsScribe = true
		selfEntry.ScribeAPIAddr = cfg.Scribe.Listen
	}
	table.UpsertForce(selfEntry)

	// Register services from config.
	for _, svc := range cfg.DNS.Services {
		RegisterService(table, identity.NodeID, cfg.Node.Addr, identity.PublicKey, isCA,
			ServiceRecord{Name: svc.Name, Port: svc.Port, Priority: svc.Priority})
	}

	// DNS server gets a callback to serve NetworkConfig zones.
	n.dns = NewDNSServer(cfg.DNS.Listen, table, func() []DNSZone { return n.netCfg.dnsZones() })
	n.socks = NewSOCKSServer(cfg.SOCKS.Listen, router, table, exitRoutes, identity.NodeID, func() []DNSZone { return n.netCfg.dnsZones() })
	n.nat = NewNATManager(identity.NodeID, table, registry, router, n.clientTLSConfig(), n.onPeerSession)

	if isScribe {
		n.scribe = NewScribe(n)
	}

	// Wire token use-count tracking: CA notifies scribe when a token is consumed.
	if ca != nil && n.scribe != nil {
		ca.OnTokenUsed = func(tokenValue string) {
			n.scribe.IncrementTokenUse(tokenValue)
		}
	}

	// Tun device (optional, Linux only).
	if cfg.Tun.Enabled {
		tun, err := NewTunDevice(n, cfg.Tun.Name, cfg.Tun.CIDR)
		if err != nil {
			Warnf("tun: init failed: %v — tun disabled", err)
		} else {
			n.tun = tun
			// Advertise mesh IP in gossip self-entry.
			if self, ok := table.Get(identity.NodeID); ok {
				self.MeshIP = MeshIPFromNodeID(identity.NodeID).String()
				table.UpsertForce(self)
			}
		}
	}

	Infof("pulse node %s starting (ws=%s tcp=%s ca=%v exit=%v scribe=%v tun=%v joined=%v)",
		identity.NodeID, cfg.Node.Addr, cfg.Node.TCPListen, isCA, isExit, isScribe, cfg.Tun.Enabled, identity.Joined)
	return n, nil
}

func (n *Node) Run(ctx context.Context) error {
	// DNS TXT bootstrap — discover additional relay addresses before connecting.
	if n.cfg.Bootstrap.DNSDomain != "" {
		dnsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		addrs, err := resolveDNSBootstrap(dnsCtx, n.cfg.Bootstrap.DNSDomain)
		cancel()
		if err != nil {
			Infof("DNS bootstrap from %s: %v", n.cfg.Bootstrap.DNSDomain, err)
		} else {
			for _, a := range addrs {
				if !slices.Contains(n.cfg.Bootstrap.Peers, a) {
					n.cfg.Bootstrap.Peers = append(n.cfg.Bootstrap.Peers, a)
					Debugf("DNS bootstrap: added relay %s", a)
				}
			}
		}
	}

	go n.serveWS(ctx)
	go n.serveQUIC(ctx)

	// Bootstrap connections use InsecureSkipVerify because the peer may not
	// have a CA-signed cert yet (e.g. a relay waiting to join). Trust is
	// established at the application layer via the handshake.
	bootstrapTLS := &tls.Config{
		Certificates:       []tls.Certificate{n.identity.TLSCert},
		InsecureSkipVerify: true,
	}
	for _, peer := range n.cfg.Bootstrap.Peers {
		p := peer
		go connectBestTransport(ctx, p, bootstrapTLS, func(session Session) {
			n.onPeerSession(ctx, session, p, "")
		})
	}

	go func() {
		if err := ServeTCP(n.cfg.Node.TCPListen, n.router, n.aclTable, n.id, n.netCfg.isRevoked); err != nil {
			Errorf("tcp listener error: %v", err)
		}
	}()

	go n.gossipLoop(ctx)
	go n.table.RunPruner(ctx, n.id)
	go n.prober.Run(ctx)
	go n.nat.Run(ctx)

	if n.cfg.SOCKS.Enabled {
		go n.socks.ListenAndServe(ctx)
	}
	if n.cfg.DNS.Enabled {
		go n.dns.ListenAndServe(ctx)
	}
	if n.scribe != nil {
		go n.scribe.Run(ctx)
	}
	if n.tun != nil {
		go n.tun.Run(ctx)
	}
	if n.cfg.Control.Socket != "" {
		ctrl := NewControlServer(n.cfg.Control.Socket, n)
		go func() {
			if err := ctrl.ListenAndServe(ctx); err != nil {
				Errorf("control socket: %v", err)
			}
		}()
	}

	// Certificate renewal loop.
	if n.identity.Joined {
		go n.certRenewalLoop(ctx)
	}

	// Peer table persistence loop.
	if n.cfg.Persist.Enabled {
		interval := time.Duration(n.cfg.Persist.Interval) * time.Second
		if interval <= 0 {
			interval = 60 * time.Second
		}
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					n.savePeers()
					return
				case <-ticker.C:
					n.savePeers()
				}
			}
		}()
	}

	select {
	case <-ctx.Done():
	case <-n.shutdown:
	}
	return nil
}

// Stop triggers a graceful shutdown of the node.
func (n *Node) Stop() {
	select {
	case <-n.shutdown:
	default:
		close(n.shutdown)
	}
}

func (n *Node) savePeers() {
	entries := n.table.Snapshot()
	filtered := entries[:0]
	for _, e := range entries {
		if e.NodeID != n.id {
			filtered = append(filtered, e)
		}
	}
	if err := SavePeers(n.cfg.Node.DataDir, filtered); err != nil {
		Debugf("persist: %v", err)
	}
}

// certRenewalLoop checks cert expiry hourly and auto-renews when <30 days remain.
func (n *Node) certRenewalLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.checkCertRenewal(ctx)
		}
	}
}

func (n *Node) checkCertRenewal(ctx context.Context) {
	cert := n.identity.TLSCert
	if len(cert.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	remaining := time.Until(leaf.NotAfter)
	if remaining > 30*24*time.Hour {
		return
	}
	Infof("cert: %s remaining — initiating renewal", remaining.Round(time.Hour))
	if err := n.renewCert(ctx); err != nil {
		Warnf("cert: renewal failed: %v", err)
	}
}

func (n *Node) renewCert(ctx context.Context) error {
	req := JoinRequest{
		PublicKey: ed25519.PublicKey(n.identity.PublicKey),
		Token:     n.cfg.Join.Token,
	}
	resp := n.resolveJoin(req)
	if resp.Error != "" {
		return fmt.Errorf("CA rejected renewal: %s", resp.Error)
	}
	if err := StoreJoinResult(n.cfg.Node.DataDir, resp); err != nil {
		return err
	}
	Infof("cert: renewed successfully")
	return n.ReloadIdentity()
}

// listenAddr returns the address to bind listeners to.
// If cfg.Node.Listen is set it is used; otherwise cfg.Node.Addr.
// This lets nodes advertise a public IP/hostname while binding to 0.0.0.0 or a private IP.
// ReloadIdentity reloads the identity from disk (after a successful join).
func (n *Node) ReloadIdentity() error {
	id, err := LoadOrCreateIdentity(n.cfg.Node.DataDir)
	if err != nil {
		return err
	}
	n.identity = id
	Infof("identity reloaded: joined=%v", id.Joined)
	return nil
}

func (n *Node) listenAddr() string {
	if n.cfg.Node.Listen != "" {
		return n.cfg.Node.Listen
	}
	return n.cfg.Node.Addr
}

func (n *Node) serveQUIC(ctx context.Context) {
	if err := listenQUIC(n.listenAddr(), n.serverTLSConfig(), func(session Session, remoteAddr string) {
		callerID := ""
		Infof("inbound QUIC peer from %s", remoteAddr)
		n.onPeerSession(ctx, session, remoteAddr, callerID)
	}); err != nil {
		Errorf("QUIC listener failed: %v (WebSocket only)", err)
	}
}

func (n *Node) serveWS(ctx context.Context) {
	mux := http.NewServeMux()

	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		// Enforce mTLS for peer connections: reject if no valid client cert.
		if n.identity.CAPool != nil && (r.TLS == nil || len(r.TLS.PeerCertificates) == 0) {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}
		callerID := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			callerID = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		serveWebSocket(ctx, w, r, func(session Session, remoteAddr string) {
			Infof("inbound peer from %s (node=%s)", remoteAddr, callerID)
			n.onPeerSession(ctx, session, remoteAddr, callerID)
		})
	})

	mux.HandleFunc("/join", func(w http.ResponseWriter, r *http.Request) {
		serveWebSocket(ctx, w, r, func(session Session, remoteAddr string) {
			Infof("join attempt from %s", remoteAddr)
			conn, err := session.Accept()
			if err != nil {
				return
			}
			n.handleJoinConn(conn)
		})
	})

	// /whoami returns the caller's observed public IP:port (for NAT discovery).
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.RemoteAddr)
	})

	srv := &http.Server{
		Addr:      n.listenAddr(),
		Handler:   mux,
		TLSConfig: n.serverTLSConfig(),
	}

	Infof("WebSocket listener on %s (advertised: %s)", n.listenAddr(), n.cfg.Node.Addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		Errorf("WS server: %v", err)
	}
}

func (n *Node) handleJoinConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	var msg streamMsg
	if err := json.Unmarshal([]byte(line), &msg); err != nil || msg.Type != "join" || msg.JoinReq == nil {
		return
	}
	resp := n.resolveJoin(*msg.JoinReq)
	reply, _ := json.Marshal(streamMsg{Type: "join_response", JoinResp: &resp})
	conn.Write(append(reply, '\n'))
}

func (n *Node) resolveJoin(req JoinRequest) JoinResponse {
	if n.ca != nil {
		return n.ca.HandleJoin(req)
	}
	caEntry, ok := n.table.FindCA()
	if !ok {
		return JoinResponse{Error: "CA node not reachable from this relay"}
	}
	session, err := n.router.Resolve(caEntry.NodeID)
	if err != nil {
		return JoinResponse{Error: fmt.Sprintf("no route to CA: %v", err)}
	}
	conn, err := session.Open()
	if err != nil {
		return JoinResponse{Error: fmt.Sprintf("open stream to CA: %v", err)}
	}
	defer conn.Close()

	fwd, _ := json.Marshal(streamMsg{Type: "join", JoinReq: &req})
	conn.Write(append(fwd, '\n'))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return JoinResponse{Error: "no response from CA"}
	}
	var reply streamMsg
	if err := json.Unmarshal([]byte(line), &reply); err != nil || reply.JoinResp == nil {
		return JoinResponse{Error: "malformed CA response"}
	}
	return *reply.JoinResp
}

// Join connects to a relay's /join endpoint for first-time bootstrapping.
func Join(ctx context.Context, relayAddr string, req JoinRequest) (*JoinResponse, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	session, err := dialPeer(ctx, relayAddr, tlsCfg, "/join")
	if err != nil {
		return nil, fmt.Errorf("connect to relay: %w", err)
	}
	defer session.Close()

	conn, err := session.Open()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	msg, _ := json.Marshal(streamMsg{Type: "join", JoinReq: &req})
	conn.Write(append(msg, '\n'))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	var reply streamMsg
	if err := json.Unmarshal([]byte(line), &reply); err != nil || reply.JoinResp == nil {
		return nil, errors.New("malformed join response")
	}
	if reply.JoinResp.Error != "" {
		return nil, errors.New(reply.JoinResp.Error)
	}
	return reply.JoinResp, nil
}

func (n *Node) onPeerSession(ctx context.Context, session Session, hint, callerID string) {
	go n.sendHandshake(session)
	for {
		conn, err := session.Accept()
		if err != nil {
			break
		}
		go n.dispatchStream(&authedConn{Conn: conn, callerNodeID: callerID, session: session})
	}
}

func (n *Node) sendHandshake(session Session) {
	conn, err := session.Open()
	if err != nil {
		return
	}
	defer conn.Close()

	// Include mesh IP if tun is active.
	meshIP := ""
	if n.cfg.Tun.Enabled {
		meshIP = MeshIPFromNodeID(n.id).String()
	}

	scribeAPIAddr := ""
	if n.cfg.Scribe.Enabled {
		scribeAPIAddr = n.cfg.Scribe.Listen
	}
	msg := streamMsg{
		Type:          "handshake",
		NodeID:        n.id,
		NetworkID:     n.cfg.Node.NetworkID,
		Addr:          n.cfg.Node.Addr,
		PublicKey:     n.identity.PublicKey,
		IsCA:          n.ca != nil,
		IsExit:        n.cfg.Exit.Enabled,
		IsScribe:      n.cfg.Scribe.Enabled,
		ScribeAPIAddr: scribeAPIAddr,
		MeshIP:        meshIP,
	}
	line, _ := json.Marshal(msg)
	conn.Write(append(line, '\n'))
}

func (n *Node) dispatchStream(ac *authedConn) {
	reader := bufio.NewReader(ac)
	line, err := reader.ReadString('\n')
	if err != nil {
		ac.Close()
		return
	}
	var msg streamMsg
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		ac.Close()
		return
	}

	// Revocation check: reject any stream (except handshake itself) from a revoked node.
	if msg.Type != "handshake" && ac.callerNodeID != "" && n.netCfg.isRevoked(ac.callerNodeID) {
		Warnf("revocation: rejected stream type=%q from %s", msg.Type, ac.callerNodeID)
		ac.Close()
		return
	}

	switch msg.Type {
	case "handshake":
		n.handleHandshake(msg, ac)
		ac.Close()

	case "gossip":
		n.table.MergeFrom(msg.Entries, n.id)
		// ACLs from gossip are unsigned — only scribe-signed NetworkConfig ACLs are trusted.
		Debugf("gossip: merged %d entries", len(msg.Entries))
		ac.Close()

	case "probe":
		pong, _ := json.Marshal(streamMsg{Type: "pong", SentAt: msg.SentAt})
		ac.Write(append(pong, '\n'))
		ac.Close()

	case "join":
		if msg.JoinReq == nil {
			ac.Close()
			return
		}
		resp := n.resolveJoin(*msg.JoinReq)
		reply, _ := json.Marshal(streamMsg{Type: "join_response", JoinResp: &resp})
		ac.Write(append(reply, '\n'))
		ac.Close()

	case "punch":
		go n.nat.HandlePunchRequest(context.Background(),
			msg.PunchNodeID, msg.PunchAddr, msg.PunchToken, msg.PunchAt)
		ac.Close()

	case "netconfig":
		if msg.NetConfig != nil {
			n.mergeNetConfig(*msg.NetConfig)
		}
		ac.Close()

	case "stats":
		if msg.Stats != nil && n.scribe != nil {
			n.scribe.AcceptStats(*msg.Stats)
		}
		ac.Close()

	case "revoke":
		// A node forwarding a revoke request to the scribe.
		if msg.RevokeNodeID != "" && n.scribe != nil {
			go n.scribe.Revoke(context.Background(), msg.RevokeNodeID)
		}
		ac.Close()

	case "tunpipe":
		// Persistent bidirectional packet pipe — one per peer pair.
		// The remote side initiated; run the pipe read loop (blocks until closed).
		if n.tun != nil {
			n.tun.RunPipe(msg.NodeID, ac.Conn)
		} else {
			ac.Close()
		}

	case "tun":
		// Legacy one-shot stream, used before a pipe is established.
		if n.tun != nil {
			n.tun.HandleInbound(ac.Conn)
		} else {
			ac.Close()
		}

	case "tunnel":
		req := TunnelRequest{DestNodeID: msg.DestNodeID, DestAddr: msg.DestAddr}
		callerID := ac.callerNodeID
		if callerID == "" {
			callerID = msg.NodeID // fallback: use handshake-announced ID
		}
		if n.netCfg.isRevoked(req.DestNodeID) {
			Warnf("tunnel: dest %s is revoked — dropping", req.DestNodeID)
			ac.Close()
			return
		}
		HandleRelayStream(ac.Conn, reader, req, n.id, callerID, n.router, n.aclTable, n.netCfg.nodeMeta)

	default:
		Infof("unknown stream type: %q", msg.Type)
		ac.Close()
	}
}

// mergeNetConfig accepts a SignedNetConfig from the scribe, verifies it, and
// if the version is newer, applies it and propagates to all peers.
func (n *Node) mergeNetConfig(snc SignedNetConfig) {
	// Look up scribe public key from gossip table.
	scribeEntry, ok := n.table.Get(snc.ScribeID)
	if !ok {
		Infof("netconfig: scribe %s not in table — ignoring", snc.ScribeID)
		return
	}
	if len(scribeEntry.PublicKey) == 0 {
		Infof("netconfig: scribe %s has no public key in gossip table — ignoring", snc.ScribeID)
		return
	}
	if err := VerifyNetConfig(snc, scribeEntry.PublicKey); err != nil {
		Warnf("netconfig: verification failed: %v", err)
		return
	}
	if !n.netCfg.merge(snc) {
		return // not newer
	}
	Warnf("netconfig: v%d applied (%d revoked, %d dns zones, %d node meta)",
		snc.Config.Version, len(snc.Config.RevokedIDs), len(snc.Config.DNSZones), len(snc.Config.NodeMeta))

	// Overlay node metadata onto gossip table entries.
	for nodeID, meta := range snc.Config.NodeMeta {
		if entry, ok := n.table.Get(nodeID); ok {
			entry.Name = meta.Name
			entry.Tags = meta.Tags
			n.table.UpsertForce(entry)
		}
	}

	// Sync ACL table from scribe-signed config (only trusted source).
	for _, acl := range snc.Config.GlobalACLs {
		n.aclTable.Upsert(acl)
	}

	// Keep CA in sync with scribe state.
	if n.ca != nil {
		n.ca.SyncRevokedIDs(snc.Config.RevokedIDs)
		n.ca.SyncTokens(snc.Config.JoinTokens)
	}

	// Propagate to all peers (flood — scribe is authoritative, Version prevents loops).
	for _, link := range n.registry.All() {
		if link.IsClosed() {
			continue
		}
		conn, err := link.Open()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			msg, _ := marshalStreamMsg(streamMsg{Type: "netconfig", NetConfig: &snc})
			c.Write(msg)
		}(conn)
	}
}

func (n *Node) handleHandshake(msg streamMsg, ac *authedConn) {
	if msg.NodeID == "" {
		return
	}
	callerID := ac.callerNodeID
	nodeID := callerID
	if nodeID == "" {
		nodeID = msg.NodeID
	}

	// Verify that the announced nodeID matches the public key.
	if len(msg.PublicKey) > 0 {
		expectedID := nodeIDFromKey(msg.PublicKey)
		if msg.NodeID != expectedID {
			Warnf("handshake: nodeID %s does not match public key (expected %s) — rejecting", msg.NodeID, expectedID)
			return
		}
	}

	// Reject connections from revoked nodes immediately.
	if n.netCfg.isRevoked(nodeID) {
		Warnf("handshake: rejecting revoked node %s", nodeID)
		return
	}

	// Network ID isolation: reject peers from different networks.
	myNet := n.cfg.Node.NetworkID
	peerNet := msg.NetworkID
	if myNet != "" && peerNet != "" && myNet != peerNet {
		Infof("handshake: rejecting node %s from network %q (we are %q)", nodeID, peerNet, myNet)
		return
	}

	Infof("handshake: node=%s addr=%s isCA=%v isExit=%v isScribe=%v meshIP=%s",
		nodeID, msg.Addr, msg.IsCA, msg.IsExit, msg.IsScribe, msg.MeshIP)
	n.table.Upsert(PeerEntry{
		NodeID:        nodeID,
		Addr:          msg.Addr,
		PublicKey:     msg.PublicKey,
		IsCA:          msg.IsCA,
		IsExit:        msg.IsExit,
		IsScribe:      msg.IsScribe,
		ScribeAPIAddr: msg.ScribeAPIAddr,
		MeshIP:        msg.MeshIP,
		LastSeen:      time.Now(),
		HopCount:      0,
	})

	// Register the session in the link registry so the router can use it.
	// This is the moment we first learn the peer's nodeID, so we register here.
	if ac.session != nil {
		n.registry.Add(newPeerLink(nodeID, ac.session))
		Infof("handshake: registered link to %s", nodeID)
	}

	// If we're the scribe, immediately push the current NetworkConfig to the
	// new peer so it doesn't have to wait up to 60s for the next broadcast.
	// This also covers nodes coming back online after a restart.
	if n.scribe != nil && ac.session != nil {
		go n.scribe.PushTo(ac.session)
	}

	// If TUN is active, immediately rebuild the mesh IP→nodeID map so that
	// reply packets from this newly-joined peer route correctly without waiting
	// for the background 5-second refresh tick.
	if n.tun != nil {
		n.tun.RefreshMeshIPs()
		// Initiate a persistent bidirectional pipe if the peer also has TUN.
		// Lower nodeID initiates to avoid both sides racing to open a pipe.
		if msg.MeshIP != "" && n.id < nodeID && ac.session != nil {
			go n.openTunPipe(nodeID, ac.session)
		}
	}
}

// openTunPipe opens a persistent bidirectional yamux stream to the peer for
// all TUN traffic. One stream handles both directions — no per-packet overhead.
func (n *Node) openTunPipe(nodeID string, session Session) {
	conn, err := session.Open()
	if err != nil {
		tunLog("open pipe to %s: %v", nodeID, err)
		return
	}
	hdr, _ := marshalStreamMsg(streamMsg{Type: "tunpipe", NodeID: n.id})
	if _, err := conn.Write(hdr); err != nil {
		conn.Close()
		return
	}
	n.tun.RunPipe(nodeID, conn)
}

func (n *Node) gossipLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.pushGossip()
			n.pushStatsToScribe()
		}
	}
}

func (n *Node) pushGossip() {
	currentVersion := n.table.Version()
	forceFullPush := time.Since(n.lastFullGossip) > 60*time.Second

	for _, link := range n.registry.All() {
		if link.IsClosed() {
			continue
		}

		// Delta-gossip: only send entries that changed since our last push to this peer.
		n.gossipVersionsMu.Lock()
		lastVersion := n.gossipVersions[link.NodeID]
		n.gossipVersionsMu.Unlock()

		var entries []PeerEntry
		if forceFullPush || lastVersion == 0 {
			entries = n.table.Snapshot()
		} else {
			entries = n.table.SnapshotSince(lastVersion)
			if len(entries) == 0 {
				continue // nothing changed for this peer
			}
		}

		conn, err := link.Open()
		if err != nil {
			continue
		}
		peerID := link.NodeID
		go func(c net.Conn) {
			defer c.Close()
			msg := streamMsg{Type: "gossip", Entries: entries}
			line, _ := json.Marshal(msg)
			c.Write(append(line, '\n'))

			n.gossipVersionsMu.Lock()
			n.gossipVersions[peerID] = currentVersion
			n.gossipVersionsMu.Unlock()
		}(conn)
	}

	if forceFullPush {
		n.lastFullGossip = time.Now()
	}
}

// pushStatsToScribe sends a stats report to the scribe if one is known in the mesh.
func (n *Node) pushStatsToScribe() {
	scribeEntry, ok := n.table.FindScribe()
	if !ok || scribeEntry.NodeID == n.id {
		return // we are the scribe, or no scribe known
	}
	session, err := n.router.Resolve(scribeEntry.NodeID)
	if err != nil {
		return
	}
	conn, err := session.Open()
	if err != nil {
		return
	}
	go func() {
		defer conn.Close()
		stats := NodeStats{
			NodeID:     n.id,
			ReportedAt: time.Now(),
			// TODO: wire up real counters from bridge/tunnel tracking
		}
		msg, _ := marshalStreamMsg(streamMsg{Type: "stats", Stats: &stats})
		conn.Write(msg)
	}()
}

func (n *Node) serverTLSConfig() *tls.Config {
	cfg := &tls.Config{
		// Dynamic cert: picks up renewed certs without restart.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &n.identity.TLSCert, nil
		},
	}
	if n.ca != nil {
		cfg.ClientAuth = tls.RequestClientCert
		cfg.ClientCAs = n.ca.Pool
	} else if n.identity.CAPool != nil {
		cfg.ClientAuth = tls.RequestClientCert
		cfg.ClientCAs = n.identity.CAPool
	}
	return cfg
}

func (n *Node) clientTLSConfig() *tls.Config {
	getCert := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &n.identity.TLSCert, nil
	}
	if n.identity.CAPool != nil {
		cfg := ClientTLSConfig(n.identity.TLSCert, n.identity.CAPool)
		cfg.GetClientCertificate = getCert
		return cfg
	}
	if n.ca != nil {
		cfg := ClientTLSConfig(n.identity.TLSCert, n.ca.Pool)
		cfg.GetClientCertificate = getCert
		return cfg
	}
	return &tls.Config{
		GetClientCertificate: getCert,
		InsecureSkipVerify:   true,
	}
}

// resolveDNSBootstrap queries _pulse.<domain> TXT records for relay addresses.
// Records must be formatted as: relay=host:port
func resolveDNSBootstrap(ctx context.Context, domain string) ([]string, error) {
	records, err := net.DefaultResolver.LookupTXT(ctx, "_pulse."+domain)
	if err != nil {
		return nil, err
	}
	var addrs []string
	for _, rec := range records {
		for _, field := range strings.Fields(rec) {
			if after, ok := strings.CutPrefix(field, "relay="); ok {
				addrs = append(addrs, after)
			}
		}
	}
	return addrs, nil
}
