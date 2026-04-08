package node

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/leonardomb1/pulse/config"
)

// streamMsg is the first JSON line on every yamux/QUIC stream.
type streamMsg struct {
	Type string `json:"type"`

	// handshake
	Version       string `json:"version,omitempty"`
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
	PunchNodeID string `json:"punch_node,omitempty"`
	PunchAddr   string `json:"punch_addr,omitempty"`
	PunchToken  string `json:"punch_token,omitempty"`

	// network config (distributed by scribe)
	NetConfig *SignedNetConfig `json:"net_config,omitempty"`

	// stats (pushed by nodes to scribe)
	Stats *NodeStats `json:"stats,omitempty"`

	// revoke (forwarded to scribe over mesh)
	RevokeNodeID string `json:"revoke_node_id,omitempty"`

	// remote command (sent by scribe to target node)
	RemoteCmd    string            `json:"remote_cmd,omitempty"`    // "restart", "config"
	RemoteConfig map[string]string `json:"remote_config,omitempty"` // key-value config overrides
}

// Node is a running relay instance.
type Node struct {
	id         string
	version    string
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
	traffic    TrafficCounters
	events     *EventLog
	statsRing  *StatsRing

	// Delta-gossip: track last-sent table version per peer.
	gossipVersionsMu sync.Mutex
	gossipVersions   map[string]uint64 // peerNodeID → last-sent version
	lastFullGossip   time.Time         // time of last full table push
}

func New(cfg *config.Config, ca *CA, version string) (*Node, error) {
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
	_ = exitRoutes.Load() // best-effort; no error if file missing

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

	eventsPath := filepath.Join(cfg.Node.DataDir, "events.log")
	events, err := OpenEventLog(eventsPath)
	if err != nil {
		Warnf("event log: %v — events will not be persisted", err)
	}

	n := &Node{
		id:             identity.NodeID,
		version:        version,
		cfg:            cfg,
		identity:       identity,
		ca:             ca,
		table:          table,
		registry:       registry,
		router:         router,
		prober:         NewProber(registry, table),
		aclTable:       aclTable,
		exitRoutes:     exitRoutes,
		shutdown:       make(chan struct{}),
		gossipVersions: make(map[string]uint64),
		events:         events,
		statsRing:      NewStatsRing(),
	}

	// Load cumulative stats from previous runs.
	statsPath := filepath.Join(cfg.Node.DataDir, "stats.json")
	_ = n.statsRing.LoadCumulative(statsPath)

	// Wire event log into CA for audit events.
	if ca != nil && events != nil {
		ca.Events = events
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
	n.socks = NewSOCKSServer(cfg.SOCKS.Listen, router, table, exitRoutes, identity.NodeID, func() []DNSZone { return n.netCfg.dnsZones() }, &n.traffic)
	n.prober.OnLinkDead = func(nodeID string) {
		n.emitEvent(EventEntry{Type: EventLinkDown, NodeID: nodeID, Detail: "dead link detected by prober"})
	}

	n.nat = NewNATManager(identity.NodeID, table, registry, router, n.clientTLSConfig(), n.onPeerSession)
	n.nat.onEvent = n.emitEvent

	table.OnPrune = func(nodeID string) {
		n.emitEvent(EventEntry{Type: EventLinkDown, NodeID: nodeID, Detail: "stale peer pruned"})
	}

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
				self.MeshIP = MeshIPFromNodeIDWithCIDR(identity.NodeID, cfg.Tun.CIDR).String()
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

	n.emitEvent(EventEntry{Type: EventStartup, Detail: fmt.Sprintf("node %s starting", n.id)})

	// Flush event log periodically.
	if n.events != nil {
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					n.events.Flush()
				}
			}
		}()
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
		if err := ServeTCP(n.cfg.Node.TCPListen, n.router, n.id, n.netCfg.isRevoked, &n.traffic); err != nil {
			Errorf("tcp listener error: %v", err)
		}
	}()

	go n.gossipLoop(ctx)
	go n.table.RunPruner(ctx, n.id)
	go n.prober.Run(ctx)
	go n.nat.Run(ctx)

	if n.cfg.SOCKS.Enabled {
		go func() { _ = n.socks.ListenAndServe(ctx) }()
	}
	if n.cfg.DNS.Enabled {
		go func() { _ = n.dns.ListenAndServe(ctx) }()
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
	n.emitEvent(EventEntry{Type: EventShutdown, Detail: "node stopping"})
	if n.events != nil {
		_ = n.events.Close()
	}
	_ = n.statsRing.SaveCumulative(filepath.Join(n.cfg.Node.DataDir, "stats.json"))
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

// sampleStats records a snapshot of per-peer metrics into the ring buffer.
func (n *Node) sampleStats() {
	now := time.Now()
	for _, entry := range n.table.Snapshot() {
		if entry.NodeID == n.id {
			continue
		}
		snap := StatsSnapshot{
			Timestamp: now,
			LatencyMS: entry.LatencyMS,
			LossRate:  entry.LossRate,
		}
		if n.scribe != nil {
			stats := n.scribe.Stats()
			if st, ok := stats[entry.NodeID]; ok {
				snap.BytesIn = st.BytesIn
				snap.BytesOut = st.BytesOut
				snap.ActiveConns = int(st.ActiveConns)
			}
		}
		n.statsRing.Record(entry.NodeID, snap)
	}
}

// handleRemoteCmd processes a remote command from the scribe.
func (n *Node) handleRemoteCmd(msg streamMsg) {
	switch msg.RemoteCmd {
	case "restart":
		Warnf("remote: restart command received — restarting")
		n.emitEvent(EventEntry{Type: EventStartup, Detail: "remote restart triggered"})
		go func() {
			time.Sleep(500 * time.Millisecond) // let the ack stream close
			n.Stop()
		}()
	case "config":
		Infof("remote: config update received: %v", msg.RemoteConfig)
		n.emitEvent(EventEntry{Type: EventStartup, Detail: "remote config push"})
		// Apply runtime-safe config changes.
		if v, ok := msg.RemoteConfig["log_level"]; ok {
			SetLogLevel(ParseLogLevel(v))
			Infof("remote: log level changed to %s", v)
		}
	default:
		Warnf("remote: unknown command %q", msg.RemoteCmd)
	}
}

// SendRemoteCmd sends a remote command to a target node via the mesh.
func (n *Node) SendRemoteCmd(targetNodeID string, cmd string, config map[string]string) error {
	session, err := n.router.Resolve(targetNodeID)
	if err != nil {
		return fmt.Errorf("no route to %s: %w", targetNodeID, err)
	}
	conn, err := session.Open()
	if err != nil {
		return err
	}
	defer conn.Close()
	msg, _ := marshalStreamMsg(streamMsg{
		Type:         "remote_cmd",
		RemoteCmd:    cmd,
		RemoteConfig: config,
	})
	_, _ = conn.Write(msg)
	return nil
}

// meshCIDR returns the active mesh CIDR — from NetworkConfig if available, otherwise from local config.
func (n *Node) meshCIDR() string {
	if snc := n.netCfg.get(); snc != nil && snc.Config.MeshCIDR != "" {
		return snc.Config.MeshCIDR
	}
	return n.cfg.Tun.CIDR
}

// meshIPForNode returns the mesh IP for a node, respecting manual overrides and network CIDR.
func (n *Node) meshIPForNode(nodeID string) net.IP {
	// Check for operator-assigned override in NodeMeta.
	meta := n.netCfg.nodeMeta(nodeID)
	if meta.MeshIP != "" {
		if ip := net.ParseIP(meta.MeshIP); ip != nil {
			return ip.To4()
		}
	}
	return MeshIPFromNodeIDWithCIDR(nodeID, n.meshCIDR())
}

// emitEvent writes an event to the event log if available.
func (n *Node) emitEvent(e EventEntry) {
	if n.events != nil {
		n.events.Emit(e)
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
			n.sampleStats()
		}
	}
}

func (n *Node) pushGossip() {
	// Refresh self-entry timestamp so peers don't prune us as stale.
	if self, ok := n.table.Get(n.id); ok {
		self.LastSeen = time.Now()
		n.table.UpsertForce(self)
	}

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
			_, _ = c.Write(append(line, '\n'))

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
			NodeID:      n.id,
			ReportedAt:  time.Now(),
			BytesIn:     n.traffic.BytesIn.Load(),
			BytesOut:    n.traffic.BytesOut.Load(),
			ActiveConns: int(n.traffic.ActiveConns.Load()),
		}
		msg, _ := marshalStreamMsg(streamMsg{Type: "stats", Stats: &stats})
		_, _ = conn.Write(msg)
	}()
}
