package node

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// NodeStats is a stats report pushed by a node to the scribe.
type NodeStats struct {
	NodeID      string    `json:"node_id"`
	ActiveConns int       `json:"active_conns"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
	ReportedAt  time.Time `json:"reported_at"`
}

// Scribe collects network-wide statistics, distributes NetworkConfig (DNS zones,
// revocation lists, global ACLs), and exposes an HTTP management API.
//
// A scribe is a regular node that does not forward TCP streams — it acts as
// the control plane of the mesh, while relay nodes are the data plane.
type Scribe struct {
	node *Node

	mu          sync.RWMutex
	stats       map[string]NodeStats
	revokedIDs  map[string]struct{}
	dnsZones    []DNSZone
	globalACLs  []NodeACL
	nodeMeta    map[string]NodeMeta
	tokens      []JoinToken
	templates   map[string]NodeConfig // tag pattern → config template
	version     int64
	persistPath string // path to netconfig.json
}

// scribeState is the on-disk representation of scribe state.
type scribeState struct {
	RevokedIDs []string              `json:"revoked_ids"`
	DNSZones   []DNSZone             `json:"dns_zones"`
	GlobalACLs []NodeACL             `json:"global_acls"`
	NodeMeta   map[string]NodeMeta   `json:"node_meta,omitempty"`
	Tokens     []JoinToken           `json:"tokens,omitempty"`
	Templates  map[string]NodeConfig `json:"templates,omitempty"`
}

func NewScribe(n *Node) *Scribe {
	s := &Scribe{
		node:        n,
		stats:       make(map[string]NodeStats),
		revokedIDs:  make(map[string]struct{}),
		nodeMeta:    make(map[string]NodeMeta),
		templates:   make(map[string]NodeConfig),
		persistPath: filepath.Join(n.cfg.Node.DataDir, "netconfig.json"),
	}
	s.load()
	return s
}

// load reads persisted state from disk. Silently ignored if file doesn't exist.
func (s *Scribe) load() {
	data, err := os.ReadFile(s.persistPath)
	if err != nil {
		return // first run or file removed — start fresh
	}
	var state scribeState
	if err := json.Unmarshal(data, &state); err != nil {
		Infof("scribe: load %s: %v", s.persistPath, err)
		return
	}
	for _, id := range state.RevokedIDs {
		s.revokedIDs[id] = struct{}{}
	}
	s.dnsZones = state.DNSZones
	s.globalACLs = state.GlobalACLs
	if state.NodeMeta != nil {
		s.nodeMeta = state.NodeMeta
	}
	s.tokens = state.Tokens
	if state.Templates != nil {
		s.templates = state.Templates
	}
	Infof("scribe: loaded %d DNS zones, %d revocations, %d node meta, %d tokens from disk",
		len(s.dnsZones), len(s.revokedIDs), len(s.nodeMeta), len(s.tokens))
}

// save atomically writes current state to disk.
func (s *Scribe) save() {
	s.mu.RLock()
	revoked := make([]string, 0, len(s.revokedIDs))
	for id := range s.revokedIDs {
		revoked = append(revoked, id)
	}
	meta := make(map[string]NodeMeta, len(s.nodeMeta))
	maps.Copy(meta, s.nodeMeta)
	tokens := make([]JoinToken, len(s.tokens))
	copy(tokens, s.tokens)
	templates := make(map[string]NodeConfig, len(s.templates))
	maps.Copy(templates, s.templates)
	state := scribeState{
		RevokedIDs: revoked,
		DNSZones:   s.dnsZones,
		GlobalACLs: s.globalACLs,
		NodeMeta:   meta,
		Tokens:     tokens,
		Templates:  templates,
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return
	}
	tmp := s.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		Warnf("scribe: save: %v", err)
		return
	}
	_ = os.Rename(tmp, s.persistPath)
}

// AddDNSZone upserts a DNS zone record and broadcasts updated NetworkConfig.
func (s *Scribe) AddDNSZone(zone DNSZone) error {
	if zone.Name == "" || zone.Type == "" || zone.Value == "" {
		return fmt.Errorf("name, type, and value are required")
	}
	if zone.TTL == 0 {
		zone.TTL = 300
	}
	s.mu.Lock()
	replaced := false
	for i, z := range s.dnsZones {
		if z.Name == zone.Name && z.Type == zone.Type {
			s.dnsZones[i] = zone
			replaced = true
			break
		}
	}
	if !replaced {
		s.dnsZones = append(s.dnsZones, zone)
	}
	s.mu.Unlock()
	s.node.emitEvent(EventEntry{Type: EventDNSChanged, Detail: zone.Type + " " + zone.Name})
	s.broadcastNetConfig()
	return nil
}

// RemoveDNSZone removes DNS zone records matching name (and optionally type).
func (s *Scribe) RemoveDNSZone(name, recType string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	s.mu.Lock()
	zones := s.dnsZones[:0]
	for _, z := range s.dnsZones {
		if z.Name == name && (recType == "" || z.Type == recType) {
			continue
		}
		zones = append(zones, z)
	}
	s.dnsZones = zones
	s.mu.Unlock()
	s.broadcastNetConfig()
	return nil
}

// Run starts the scribe's HTTP API and the periodic NetworkConfig broadcast.
func (s *Scribe) Run(ctx context.Context) {
	// Broadcast config immediately so nodes that connected before us get it.
	go s.broadcastNetConfig()

	// Periodic re-broadcast so new nodes always converge.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.detectMeshIPCollisions()
				s.broadcastNetConfig()
			}
		}
	}()

	apiKey := s.loadOrCreateAPIKey()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/nodes", s.handleNodes)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/revoke", s.handleRevoke)
	mux.HandleFunc("/api/dns", s.handleDNS)
	mux.HandleFunc("/api/acls", s.handleACLs)
	mux.HandleFunc("/api/tags", s.handleTags)
	mux.HandleFunc("/api/name", s.handleName)
	mux.HandleFunc("/api/mesh-ip", s.handleMeshIP)
	mux.HandleFunc("/api/templates", s.handleTemplates)
	mux.HandleFunc("/api/groups", s.handleGroups)
	mux.HandleFunc("/api/bulk", s.handleBulk)
	mux.HandleFunc("/api/pin", s.handlePin)
	mux.HandleFunc("/api/remote/restart", s.handleRemoteRestart)
	mux.HandleFunc("/api/remote/config", s.handleRemoteConfig)
	mux.HandleFunc("/api/node/", s.handleNodeDetail)
	mux.HandleFunc("/api/routes", s.handleRoutes)
	mux.HandleFunc("/api/tokens", s.handleTokens)
	mux.HandleFunc("/api/events", s.handleEventsAPI)
	mux.HandleFunc("/api/versions", s.handleVersions)
	mux.HandleFunc("/metrics", s.handleMetrics) // no auth — Prometheus scraping

	// Wrap API routes with Bearer token auth.
	handler := s.authMiddleware(apiKey, mux)

	srv := &http.Server{
		Addr:    s.node.cfg.Scribe.Listen,
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	Infof("scribe: HTTP API on %s", s.node.cfg.Scribe.Listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		Errorf("scribe: HTTP API error: %v", err)
	}
}

// loadOrCreateAPIKey reads or generates the scribe API key.
func (s *Scribe) loadOrCreateAPIKey() string {
	keyPath := filepath.Join(s.node.cfg.Node.DataDir, "scribe-api-key")
	if data, err := os.ReadFile(keyPath); err == nil {
		key := strings.TrimSpace(string(data))
		if key != "" {
			Infof("scribe: API key loaded from %s", keyPath)
			return key
		}
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	key := hex.EncodeToString(b)
	if err := os.WriteFile(keyPath, []byte(key+"\n"), 0600); err != nil {
		Warnf("scribe: could not persist API key: %v", err)
	}
	Infof("scribe: API key generated and saved to %s", keyPath)
	return key
}

// authMiddleware wraps an http.Handler with Bearer token authentication.
// The /metrics endpoint is exempt (Prometheus needs unauthenticated access).
func (s *Scribe) authMiddleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for metrics endpoint.
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		// Skip auth for requests from localhost if no Authorization header is set.
		// This preserves backwards compatibility with the control socket CLI.
		auth := r.Header.Get("Authorization")
		if auth == "" {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			if host == "127.0.0.1" || host == "::1" || host == "" {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(apiKey)) != 1 {
			http.Error(w, `{"error":"invalid API key"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// PushNodeConfig generates a signed NodeConfig for a target node and sends it via mesh.
func (s *Scribe) PushNodeConfig(nodeID string, cfg NodeConfig) {
	cfg.Version = time.Now().UnixMilli()
	if cfg.MeshCIDR == "" {
		cfg.MeshCIDR = s.node.cfg.Tun.CIDR
	}
	snc, err := SignNodeConfig(cfg, s.node.identity.PrivateKey, s.node.id)
	if err != nil {
		Warnf("scribe: sign node config for %s: %v", nodeID, err)
		return
	}
	session, err := s.node.router.Resolve(nodeID)
	if err != nil {
		Warnf("scribe: no route to %s for node config push: %v", nodeID, err)
		return
	}
	conn, err := session.Open()
	if err != nil {
		return
	}
	go func() {
		defer func() { _ = conn.Close() }()
		msg, _ := marshalStreamMsg(streamMsg{Type: "nodestate", NodeState: &snc})
		_, _ = conn.Write(msg)
	}()
	Infof("scribe: pushed node config v%d to %s", cfg.Version, nodeID)
}

// BuildNodeConfigForPeer constructs a NodeConfig for a node based on its metadata and templates.
func (s *Scribe) BuildNodeConfigForPeer(nodeID string) NodeConfig {
	s.mu.RLock()
	meta := s.nodeMeta[nodeID]
	s.mu.RUnlock()

	cfg := NodeConfig{
		MeshCIDR: s.node.cfg.Tun.CIDR,
	}
	if meta.MeshIP != "" {
		cfg.MeshIP = meta.MeshIP
	}

	// Apply matching template if available.
	s.mu.RLock()
	for pattern, tmpl := range s.templates {
		if matchTagPattern(pattern, meta.Tags) {
			cfg.TunEnabled = tmpl.TunEnabled
			cfg.SocksEnabled = tmpl.SocksEnabled
			cfg.DNSEnabled = tmpl.DNSEnabled
			cfg.ExitEnabled = tmpl.ExitEnabled
			cfg.ExitCIDRs = tmpl.ExitCIDRs
			cfg.FECEnabled = tmpl.FECEnabled
			cfg.TunQueues = tmpl.TunQueues
			cfg.LogLevel = tmpl.LogLevel
			break
		}
	}
	s.mu.RUnlock()

	return cfg
}

// PinRoute forces traffic to a node through a specific relay.
func (s *Scribe) PinRoute(nodeID, viaNodeID string) {
	s.mu.Lock()
	m := s.nodeMeta[nodeID]
	m.PinnedVia = viaNodeID
	s.nodeMeta[nodeID] = m
	s.mu.Unlock()
	Infof("scribe: pinned %s via %s", nodeID, viaNodeID)
	s.broadcastNetConfig()
}

// UnpinRoute removes a route pin from a node.
func (s *Scribe) UnpinRoute(nodeID string) {
	s.mu.Lock()
	m := s.nodeMeta[nodeID]
	m.PinnedVia = ""
	s.nodeMeta[nodeID] = m
	s.mu.Unlock()
	Infof("scribe: unpinned %s", nodeID)
	s.broadcastNetConfig()
}

// SetTemplate adds or updates a config template for a tag pattern.
func (s *Scribe) SetTemplate(pattern string, cfg NodeConfig) {
	s.mu.Lock()
	s.templates[pattern] = cfg
	s.mu.Unlock()
	s.save()
	Infof("scribe: template set for pattern %q", pattern)

	// Re-push config to all nodes matching this pattern.
	for _, entry := range s.node.table.Snapshot() {
		if entry.NodeID == s.node.id {
			continue
		}
		meta := s.nodeMeta[entry.NodeID]
		if matchTagPattern(pattern, meta.Tags) {
			go func(nodeID string) {
				nc := s.BuildNodeConfigForPeer(nodeID)
				s.PushNodeConfig(nodeID, nc)
			}(entry.NodeID)
		}
	}
}

// DeleteTemplate removes a config template.
func (s *Scribe) DeleteTemplate(pattern string) {
	s.mu.Lock()
	delete(s.templates, pattern)
	s.mu.Unlock()
	s.save()
	Infof("scribe: template deleted for pattern %q", pattern)
}

// GetTemplates returns a copy of all config templates.
func (s *Scribe) GetTemplates() map[string]NodeConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]NodeConfig, len(s.templates))
	maps.Copy(out, s.templates)
	return out
}

// matchTagPattern checks if any of the node's tags match a template pattern.
// Supports exact match and prefix match (e.g. "site:nyc" matches tag "site:nyc/floor:3").
func matchTagPattern(pattern string, tags []string) bool {
	for _, tag := range tags {
		if tag == pattern || strings.HasPrefix(tag, pattern+"/") {
			return true
		}
	}
	return false
}

// NodesByTagPattern returns nodeIDs of all nodes whose tags match the pattern.
func (s *Scribe) NodesByTagPattern(pattern string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for nodeID, meta := range s.nodeMeta {
		if matchTagPattern(pattern, meta.Tags) {
			out = append(out, nodeID)
		}
	}
	return out
}

// Groups returns a map of tag prefixes to node counts for fleet overview.
func (s *Scribe) Groups() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := make(map[string]int)
	for _, meta := range s.nodeMeta {
		for _, tag := range meta.Tags {
			counts[tag]++
		}
	}
	return counts
}

// AcceptStats stores a stats report from a peer node.
func (s *Scribe) AcceptStats(stats NodeStats) {
	stats.ReportedAt = time.Now()
	s.mu.Lock()
	s.stats[stats.NodeID] = stats
	s.mu.Unlock()
}

// Stats returns a copy of the per-node traffic stats collected from peers.
func (s *Scribe) Stats() map[string]NodeStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]NodeStats, len(s.stats))
	maps.Copy(out, s.stats)
	return out
}

// Revoke adds nodeID to the revocation list and broadcasts an updated NetworkConfig.
func (s *Scribe) Revoke(nodeID string) {
	s.mu.Lock()
	s.revokedIDs[nodeID] = struct{}{}
	s.mu.Unlock()
	Warnf("scribe: revoked node %s", nodeID)
	s.node.emitEvent(EventEntry{Type: EventNodeRevoked, NodeID: nodeID})
	s.broadcastNetConfig()
}

// buildNetConfig constructs the current NetworkConfig from scribe state.
func (s *Scribe) buildNetConfig() NetworkConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	revoked := make([]string, 0, len(s.revokedIDs))
	for id := range s.revokedIDs {
		revoked = append(revoked, id)
	}
	meta := make(map[string]NodeMeta, len(s.nodeMeta))
	for k, v := range s.nodeMeta {
		if len(v.Tags) > 0 {
			tags := make([]string, len(v.Tags))
			copy(tags, v.Tags)
			v.Tags = tags
		}
		meta[k] = v
	}
	var validTokens []JoinToken
	for _, t := range s.tokens {
		if t.IsValid() {
			validTokens = append(validTokens, t)
		}
	}
	s.version++
	return NetworkConfig{
		Version:    time.Now().UnixMilli() + s.version, // monotonically increasing
		MeshCIDR:   s.node.cfg.Tun.CIDR,
		RevokedIDs: revoked,
		DNSZones:   s.dnsZones,
		GlobalACLs: s.globalACLs,
		NodeMeta:   meta,
		JoinTokens: validTokens,
	}
}

// broadcastNetConfig signs the current NetworkConfig, persists it, and pushes
// it to all connected peers.
func (s *Scribe) broadcastNetConfig() {
	cfg := s.buildNetConfig()
	snc, err := SignNetConfig(cfg, s.node.identity.PrivateKey, s.node.id)
	if err != nil {
		Warnf("scribe: sign netconfig: %v", err)
		return
	}

	// Persist before broadcasting so state survives a restart even if no peers
	// are connected to acknowledge it.
	s.save()

	// Update our own store first.
	s.node.netCfg.merge(snc)

	for _, link := range s.node.registry.All() {
		if link.IsClosed() {
			continue
		}
		go func(l *PeerLink) {
			conn, err := l.Open()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			msg, _ := marshalStreamMsg(streamMsg{Type: "netconfig", NetConfig: &snc})
			_, _ = conn.Write(msg)
		}(link)
	}
}

// PushTo sends the current signed NetworkConfig to a single session.
// Called when a new peer connects so it gets config immediately without waiting
// for the next broadcast tick.
func (s *Scribe) PushTo(session Session) {
	cfg := s.buildNetConfig()
	snc, err := SignNetConfig(cfg, s.node.identity.PrivateKey, s.node.id)
	if err != nil {
		return
	}
	conn, err := session.Open()
	if err != nil {
		return
	}
	go func() {
		defer func() { _ = conn.Close() }()
		msg, _ := marshalStreamMsg(streamMsg{Type: "netconfig", NetConfig: &snc})
		_, _ = conn.Write(msg)
	}()
}

// SetName assigns a friendly name to a node.
func (s *Scribe) SetName(nodeID, name string) {
	s.mu.Lock()
	m := s.nodeMeta[nodeID]
	m.Name = name
	s.nodeMeta[nodeID] = m
	s.mu.Unlock()
	Infof("scribe: set name %s → %q", nodeID, name)
	s.broadcastNetConfig()
}

// SetMeshIP assigns a manual mesh IP override to a node.
func (s *Scribe) SetMeshIP(nodeID, meshIP string) {
	s.mu.Lock()
	m := s.nodeMeta[nodeID]
	m.MeshIP = meshIP
	s.nodeMeta[nodeID] = m
	s.mu.Unlock()
	Infof("scribe: set mesh IP %s → %s", nodeID, meshIP)
	s.node.emitEvent(EventEntry{Type: EventTagChanged, NodeID: nodeID, Detail: "mesh_ip=" + meshIP})
	s.broadcastNetConfig()
}

// SetTag adds a tag to a node.
func (s *Scribe) SetTag(nodeID, tag string) {
	s.mu.Lock()
	m := s.nodeMeta[nodeID]
	for _, t := range m.Tags {
		if t == tag {
			s.mu.Unlock()
			return
		}
	}
	m.Tags = append(m.Tags, tag)
	s.nodeMeta[nodeID] = m
	s.mu.Unlock()
	Infof("scribe: tag %s +%s", nodeID, tag)
	s.node.emitEvent(EventEntry{Type: EventTagChanged, NodeID: nodeID, Detail: "+" + tag})
	s.broadcastNetConfig()

	// Re-evaluate templates for this node after tag change.
	go func() {
		cfg := s.BuildNodeConfigForPeer(nodeID)
		s.PushNodeConfig(nodeID, cfg)
	}()
}

// RemoveTag removes a tag from a node.
func (s *Scribe) RemoveTag(nodeID, tag string) {
	s.mu.Lock()
	m := s.nodeMeta[nodeID]
	var tags []string
	for _, t := range m.Tags {
		if t != tag {
			tags = append(tags, t)
		}
	}
	m.Tags = tags
	s.nodeMeta[nodeID] = m
	s.mu.Unlock()
	Infof("scribe: tag %s -%s", nodeID, tag)
	s.broadcastNetConfig()
}

// CreateToken generates a new join token and broadcasts it to the CA.
func (s *Scribe) CreateToken(ttl time.Duration, maxUses int) JoinToken {
	t := GenerateToken(ttl, maxUses)
	s.mu.Lock()
	s.tokens = append(s.tokens, t)
	s.mu.Unlock()
	Infof("scribe: token created (ttl=%s, max_uses=%d)", ttl, maxUses)
	s.broadcastNetConfig()
	return t
}

// ListTokens returns all tokens (including expired, for display).
func (s *Scribe) ListTokens() []JoinToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]JoinToken, len(s.tokens))
	copy(out, s.tokens)
	return out
}

// RevokeToken removes a token by value prefix.
func (s *Scribe) RevokeToken(prefix string) error {
	s.mu.Lock()
	found := false
	tokens := s.tokens[:0]
	for _, t := range s.tokens {
		if len(t.Value) >= len(prefix) && t.Value[:len(prefix)] == prefix {
			found = true
			continue
		}
		tokens = append(tokens, t)
	}
	s.tokens = tokens
	s.mu.Unlock()
	if !found {
		return fmt.Errorf("no token matching prefix %q", prefix)
	}
	Infof("scribe: token revoked (prefix=%s)", prefix)
	s.broadcastNetConfig()
	return nil
}

// IncrementTokenUse marks a token as used once.
func (s *Scribe) IncrementTokenUse(tokenValue string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.tokens {
		if s.tokens[i].Value == tokenValue {
			s.tokens[i].UseCount++
			break
		}
	}
	s.save()
}

// AddACLRule appends a global ACL rule and broadcasts the updated config.
func (s *Scribe) AddACLRule(rule ACLRule) {
	s.mu.Lock()
	if len(s.globalACLs) == 0 {
		s.globalACLs = []NodeACL{{NodeID: "*"}}
	}
	s.globalACLs[0].Allow = append(s.globalACLs[0].Allow, rule)
	s.globalACLs[0].Version = time.Now().Unix()
	s.mu.Unlock()
	Infof("scribe: acl added %s %s → %s ports=%s",
		rule.action(), rule.SrcPattern, rule.DstPattern, FormatPortRanges(rule.Ports))
	s.node.emitEvent(EventEntry{Type: EventACLChanged, Detail: rule.SrcPattern + " → " + rule.DstPattern})
	s.broadcastNetConfig()
}

// RemoveACLRule removes a global ACL rule by index and broadcasts.
func (s *Scribe) RemoveACLRule(index int) error {
	s.mu.Lock()
	if len(s.globalACLs) == 0 || index < 0 || index >= len(s.globalACLs[0].Allow) {
		s.mu.Unlock()
		return fmt.Errorf("rule index %d out of range", index)
	}
	rules := s.globalACLs[0].Allow
	s.globalACLs[0].Allow = append(rules[:index], rules[index+1:]...)
	s.globalACLs[0].Version = time.Now().Unix()
	s.mu.Unlock()
	Infof("scribe: acl removed rule #%d", index)
	s.broadcastNetConfig()
	return nil
}

// GlobalACLRules returns a copy of the current global ACL rules.
func (s *Scribe) GlobalACLRules() []ACLRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.globalACLs) == 0 {
		return nil
	}
	out := make([]ACLRule, len(s.globalACLs[0].Allow))
	copy(out, s.globalACLs[0].Allow)
	return out
}

// detectMeshIPCollisions checks all nodes in the gossip table for mesh IP
// collisions. If two nodes derive the same IP, the one that joined later
// (by LastSeen) gets a free IP assigned via SetMeshIP.
func (s *Scribe) detectMeshIPCollisions() {
	cidr := s.node.cfg.Tun.CIDR
	if cidr == "" {
		return
	}

	entries := s.node.table.Snapshot()
	// ipOwner maps derived mesh IP → nodeID of the earliest-seen node using it.
	ipOwner := make(map[string]string, len(entries))
	// Track all used IPs (both derived and manually assigned).
	usedIPs := make(map[string]bool, len(entries))

	s.mu.RLock()
	// First pass: collect manually assigned IPs.
	for nodeID, meta := range s.nodeMeta {
		if meta.MeshIP != "" {
			usedIPs[meta.MeshIP] = true
			ipOwner[meta.MeshIP] = nodeID
		}
	}
	s.mu.RUnlock()

	// Sort entries by LastSeen so earlier nodes keep their IP.
	// We process in order and the first node to claim an IP wins.
	type nodeIP struct {
		nodeID   string
		ip       string
		lastSeen time.Time
	}
	var derived []nodeIP
	for _, e := range entries {
		s.mu.RLock()
		meta := s.nodeMeta[e.NodeID]
		s.mu.RUnlock()
		if meta.MeshIP != "" {
			continue // manually assigned, skip
		}
		ip := MeshIPFromNodeIDWithCIDR(e.NodeID, cidr).String()
		derived = append(derived, nodeIP{nodeID: e.NodeID, ip: ip, lastSeen: e.LastSeen})
	}

	// Sort by LastSeen ascending (earliest first keeps their IP).
	for i := 1; i < len(derived); i++ {
		for j := i; j > 0 && derived[j].lastSeen.Before(derived[j-1].lastSeen); j-- {
			derived[j], derived[j-1] = derived[j-1], derived[j]
		}
	}

	for _, d := range derived {
		if owner, exists := ipOwner[d.ip]; exists && owner != d.nodeID {
			// Collision: this node joined later, assign a free IP.
			freeIP := findFreeMeshIP(cidr, usedIPs)
			if freeIP == "" {
				Warnf("scribe: no free mesh IP for collision resolution (node %s)", d.nodeID)
				continue
			}
			Infof("scribe: mesh IP collision %s between %s and %s, reassigning %s → %s",
				d.ip, owner, d.nodeID, d.nodeID, freeIP)
			usedIPs[freeIP] = true
			ipOwner[freeIP] = d.nodeID
			s.SetMeshIP(d.nodeID, freeIP)
		} else {
			usedIPs[d.ip] = true
			ipOwner[d.ip] = d.nodeID
		}
	}
}

// findFreeMeshIP iterates host addresses in the CIDR to find one not in usedIPs.
func findFreeMeshIP(cidr string, usedIPs map[string]bool) string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	prefix := ipNet.IP.To4()
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	maxHost := (uint32(1) << hostBits) - 2
	netAddr := (uint32(prefix[0]) << 24) | (uint32(prefix[1]) << 16) |
		(uint32(prefix[2]) << 8) | uint32(prefix[3])

	for h := uint32(1); h <= maxHost; h++ {
		ipVal := netAddr + h
		ip := net.IP{byte(ipVal >> 24), byte(ipVal >> 16), byte(ipVal >> 8), byte(ipVal)}
		if !usedIPs[ip.String()] {
			return ip.String()
		}
	}
	return ""
}

// HTTP handlers are in scribe_api.go.
