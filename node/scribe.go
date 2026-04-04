package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
	for k, v := range s.nodeMeta {
		meta[k] = v
	}
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
	os.Rename(tmp, s.persistPath)
}

// AddDNSZone upserts a DNS zone record and broadcasts updated NetworkConfig.
func (s *Scribe) AddDNSZone(ctx context.Context, zone DNSZone) error {
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
	s.broadcastNetConfig(ctx)
	return nil
}

// RemoveDNSZone removes DNS zone records matching name (and optionally type).
func (s *Scribe) RemoveDNSZone(ctx context.Context, name, recType string) error {
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
	s.broadcastNetConfig(ctx)
	return nil
}

// Run starts the scribe's HTTP API and the periodic NetworkConfig broadcast.
func (s *Scribe) Run(ctx context.Context) {
	// Broadcast config immediately so nodes that connected before us get it.
	go s.broadcastNetConfig(ctx)

	// Periodic re-broadcast so new nodes always converge.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.broadcastNetConfig(ctx)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/nodes", s.handleNodes)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/revoke", s.handleRevoke)
	mux.HandleFunc("/api/dns", s.handleDNS)
	mux.HandleFunc("/api/acls", s.handleACLs)
	mux.HandleFunc("/api/tags", s.handleTags)
	mux.HandleFunc("/api/name", s.handleName)
	mux.HandleFunc("/api/routes", s.handleRoutes)
	mux.HandleFunc("/metrics", s.handleMetrics)

	srv := &http.Server{
		Addr:    s.node.cfg.Scribe.Listen,
		Handler: mux,
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

// AcceptStats stores a stats report from a peer node.
func (s *Scribe) AcceptStats(stats NodeStats) {
	stats.ReportedAt = time.Now()
	s.mu.Lock()
	s.stats[stats.NodeID] = stats
	s.mu.Unlock()
}

// Revoke adds nodeID to the revocation list and broadcasts an updated NetworkConfig.
func (s *Scribe) Revoke(ctx context.Context, nodeID string) {
	s.mu.Lock()
	s.revokedIDs[nodeID] = struct{}{}
	s.mu.Unlock()
	Warnf("scribe: revoked node %s", nodeID)
	s.broadcastNetConfig(ctx)
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
		RevokedIDs: revoked,
		DNSZones:   s.dnsZones,
		GlobalACLs: s.globalACLs,
		NodeMeta:   meta,
		JoinTokens: validTokens,
	}
}

// broadcastNetConfig signs the current NetworkConfig, persists it, and pushes
// it to all connected peers.
func (s *Scribe) broadcastNetConfig(ctx context.Context) {
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
			conn.Write(msg)
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
		conn.Write(msg)
	}()
}

// SetName assigns a friendly name to a node.
func (s *Scribe) SetName(ctx context.Context, nodeID, name string) {
	s.mu.Lock()
	m := s.nodeMeta[nodeID]
	m.Name = name
	s.nodeMeta[nodeID] = m
	s.mu.Unlock()
	Infof("scribe: set name %s → %q", nodeID, name)
	s.broadcastNetConfig(ctx)
}

// SetTag adds a tag to a node.
func (s *Scribe) SetTag(ctx context.Context, nodeID, tag string) {
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
	s.broadcastNetConfig(ctx)
}

// RemoveTag removes a tag from a node.
func (s *Scribe) RemoveTag(ctx context.Context, nodeID, tag string) {
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
	s.broadcastNetConfig(ctx)
}

// CreateToken generates a new join token and broadcasts it to the CA.
func (s *Scribe) CreateToken(ctx context.Context, ttl time.Duration, maxUses int) JoinToken {
	t := GenerateToken(ttl, maxUses)
	s.mu.Lock()
	s.tokens = append(s.tokens, t)
	s.mu.Unlock()
	Infof("scribe: token created (ttl=%s, max_uses=%d)", ttl, maxUses)
	s.broadcastNetConfig(ctx)
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
func (s *Scribe) RevokeToken(ctx context.Context, prefix string) error {
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
	s.broadcastNetConfig(ctx)
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
func (s *Scribe) AddACLRule(ctx context.Context, rule ACLRule) {
	s.mu.Lock()
	if len(s.globalACLs) == 0 {
		s.globalACLs = []NodeACL{{NodeID: "*"}}
	}
	s.globalACLs[0].Allow = append(s.globalACLs[0].Allow, rule)
	s.globalACLs[0].Version = time.Now().Unix()
	s.mu.Unlock()
	Infof("scribe: acl added %s %s → %s ports=%s",
		rule.action(), rule.SrcPattern, rule.DstPattern, FormatPortRanges(rule.Ports))
	s.broadcastNetConfig(ctx)
}

// RemoveACLRule removes a global ACL rule by index and broadcasts.
func (s *Scribe) RemoveACLRule(ctx context.Context, index int) error {
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
	s.broadcastNetConfig(ctx)
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

// --- HTTP handlers ---

func (s *Scribe) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peers := s.node.table.Snapshot()
	// Enrich peers with derived mesh IPs where missing.
	for i := range peers {
		if peers[i].MeshIP == "" {
			peers[i].MeshIP = MeshIPFromNodeID(peers[i].NodeID).String()
		}
	}

	s.mu.RLock()
	stats := make(map[string]NodeStats, len(s.stats))
	for k, v := range s.stats {
		stats[k] = v
	}
	revoked := make([]string, 0, len(s.revokedIDs))
	for id := range s.revokedIDs {
		revoked = append(revoked, id)
	}
	meta := make(map[string]NodeMeta, len(s.nodeMeta))
	for k, v := range s.nodeMeta {
		meta[k] = v
	}
	var aclRules []ACLRule
	if len(s.globalACLs) > 0 {
		aclRules = s.globalACLs[0].Allow
	}
	s.mu.RUnlock()

	resp := struct {
		Peers      []PeerEntry          `json:"peers"`
		Stats      map[string]NodeStats `json:"stats"`
		RevokedIDs []string             `json:"revoked_ids"`
		NodeMeta   map[string]NodeMeta  `json:"node_meta"`
		ACLRules   []ACLRule            `json:"acl_rules"`
		ScribeID   string               `json:"scribe_id"`
		NetworkID  string               `json:"network_id"`
		MeshCIDR   string               `json:"mesh_cidr"`
	}{
		Peers:      peers,
		Stats:      stats,
		RevokedIDs: revoked,
		NodeMeta:   meta,
		ACLRules:   aclRules,
		ScribeID:   s.node.id,
		NetworkID:  s.node.cfg.Node.NetworkID,
		MeshCIDR:   s.node.cfg.Tun.CIDR,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Scribe) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peers := s.node.table.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

func (s *Scribe) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.buildNetConfig()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)

	case http.MethodPut:
		// Operator pushes new DNS zones or global ACLs.
		var update struct {
			DNSZones   []DNSZone `json:"dns_zones"`
			GlobalACLs []NodeACL `json:"global_acls"`
		}
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		if update.DNSZones != nil {
			s.dnsZones = update.DNSZones
		}
		if update.GlobalACLs != nil {
			s.globalACLs = update.GlobalACLs
		}
		s.mu.Unlock()
		s.broadcastNetConfig(r.Context())
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Scribe) handleDNS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		zones := s.dnsZones
		s.mu.RUnlock()
		if zones == nil {
			zones = []DNSZone{}
		}
		json.NewEncoder(w).Encode(zones)

	case http.MethodPost:
		var zone DNSZone
		if err := json.NewDecoder(r.Body).Decode(&zone); err != nil || zone.Name == "" || zone.Type == "" || zone.Value == "" {
			http.Error(w, `{"error":"name, type, and value required"}`, http.StatusBadRequest)
			return
		}
		if err := s.AddDNSZone(r.Context(), zone); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case http.MethodDelete:
		var req struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, `{"error":"name required"}`, http.StatusBadRequest)
			return
		}
		if err := s.RemoveDNSZone(r.Context(), req.Name, req.Type); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Scribe) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}
	s.Revoke(r.Context(), req.NodeID)

	if s.node.ca != nil {
		s.node.ca.RevokeNode(req.NodeID)
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleACLs manages global ACL rules.
//
//	GET    /api/acls              list rules
//	POST   /api/acls              add a rule
//	DELETE /api/acls {"index":N}  remove rule by index
func (s *Scribe) handleACLs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		rules := s.GlobalACLRules()
		if rules == nil {
			rules = []ACLRule{}
		}
		json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		var rule ACLRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, `{"error":"invalid rule"}`, http.StatusBadRequest)
			return
		}
		s.AddACLRule(r.Context(), rule)
		w.WriteHeader(http.StatusNoContent)

	case http.MethodDelete:
		var req struct {
			Index int `json:"index"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"index required"}`, http.StatusBadRequest)
			return
		}
		if err := s.RemoveACLRule(r.Context(), req.Index); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTags manages node tags.
//
//	POST   /api/tags {"node_id":"...", "tag":"..."}           add tag
//	DELETE /api/tags {"node_id":"...", "tag":"..."}           remove tag
func (s *Scribe) handleTags(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID string `json:"node_id"`
		Tag    string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == "" || req.Tag == "" {
		http.Error(w, `{"error":"node_id and tag required"}`, http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.SetTag(r.Context(), req.NodeID, req.Tag)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		s.RemoveTag(r.Context(), req.NodeID, req.Tag)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRoutes returns the node's exit route table.
//
//	GET /api/routes
func (s *Scribe) handleRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	routes := s.node.exitRoutes.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(routes)
}

// handleName sets a node's friendly name.
//
//	PUT /api/name {"node_id":"...", "name":"..."}
func (s *Scribe) handleName(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		Name   string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == "" {
		http.Error(w, `{"error":"node_id required"}`, http.StatusBadRequest)
		return
	}
	s.SetName(r.Context(), req.NodeID, req.Name)
	w.WriteHeader(http.StatusNoContent)
}
