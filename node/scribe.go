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
	version     int64
	persistPath string // path to netconfig.json
}

// scribeState is the on-disk representation of scribe state.
type scribeState struct {
	RevokedIDs []string            `json:"revoked_ids"`
	DNSZones   []DNSZone           `json:"dns_zones"`
	GlobalACLs []NodeACL           `json:"global_acls"`
	NodeMeta   map[string]NodeMeta `json:"node_meta,omitempty"`
	Tokens     []JoinToken         `json:"tokens,omitempty"`
}

func NewScribe(n *Node) *Scribe {
	s := &Scribe{
		node:        n,
		stats:       make(map[string]NodeStats),
		revokedIDs:  make(map[string]struct{}),
		nodeMeta:    make(map[string]NodeMeta),
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
	state := scribeState{
		RevokedIDs: revoked,
		DNSZones:   s.dnsZones,
		GlobalACLs: s.globalACLs,
		NodeMeta:   meta,
		Tokens:     tokens,
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
	mux.HandleFunc("/api/remote/restart", s.handleRemoteRestart)
	mux.HandleFunc("/api/remote/config", s.handleRemoteConfig)
	mux.HandleFunc("/api/node/", s.handleNodeDetail)
	mux.HandleFunc("/api/routes", s.handleRoutes)
	mux.HandleFunc("/metrics", s.handleMetrics) // no auth — Prometheus scraping

	// Wrap API routes with Bearer token auth.
	handler := s.authMiddleware(apiKey, mux)

	srv := &http.Server{
		Addr:    s.node.cfg.Scribe.Listen,
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		srv.Close()
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
			defer conn.Close()
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
		defer conn.Close()
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

// HTTP handlers are in scribe_api.go.
