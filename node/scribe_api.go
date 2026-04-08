package node

import (
	"encoding/json"
	"maps"
	"net"
	"net/http"
	"strings"
	"time"
)

func (s *Scribe) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peers := s.node.table.Snapshot()
	for i := range peers {
		if peers[i].MeshIP == "" {
			peers[i].MeshIP = s.node.meshIPForNode(peers[i].NodeID).String()
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
	maps.Copy(meta, s.nodeMeta)
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
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Scribe) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peers := s.node.table.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(peers)
}

func (s *Scribe) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := s.buildNetConfig()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)

	case http.MethodPut:
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
		s.broadcastNetConfig()
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
		_ = json.NewEncoder(w).Encode(zones)

	case http.MethodPost:
		var zone DNSZone
		if err := json.NewDecoder(r.Body).Decode(&zone); err != nil || zone.Name == "" || zone.Type == "" || zone.Value == "" {
			http.Error(w, `{"error":"name, type, and value required"}`, http.StatusBadRequest)
			return
		}
		if err := s.AddDNSZone(zone); err != nil {
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
		if err := s.RemoveDNSZone(req.Name, req.Type); err != nil {
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
	s.Revoke(req.NodeID)

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
		_ = json.NewEncoder(w).Encode(rules)

	case http.MethodPost:
		var rule ACLRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			http.Error(w, `{"error":"invalid rule"}`, http.StatusBadRequest)
			return
		}
		s.AddACLRule(rule)
		w.WriteHeader(http.StatusNoContent)

	case http.MethodDelete:
		var req struct {
			Index int `json:"index"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"index required"}`, http.StatusBadRequest)
			return
		}
		if err := s.RemoveACLRule(req.Index); err != nil {
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
		s.SetTag(req.NodeID, req.Tag)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		s.RemoveTag(req.NodeID, req.Tag)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRoutes manages exit routes.
//
//	GET    /api/routes
//	POST   /api/routes {"cidr":"10.0.0.0/8", "via":"node-id"}
//	DELETE /api/routes {"cidr":"10.0.0.0/8"}
func (s *Scribe) handleRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		routes := s.node.exitRoutes.Snapshot()
		_ = json.NewEncoder(w).Encode(routes)
	case http.MethodPost:
		var req struct {
			CIDR string `json:"cidr"`
			Via  string `json:"via"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CIDR == "" || req.Via == "" {
			http.Error(w, `{"error":"cidr and via required"}`, http.StatusBadRequest)
			return
		}
		if err := s.node.exitRoutes.Add(req.CIDR, req.Via); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		_ = s.node.exitRoutes.Save()
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		var req struct {
			CIDR string `json:"cidr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CIDR == "" {
			http.Error(w, `{"error":"cidr required"}`, http.StatusBadRequest)
			return
		}
		s.node.exitRoutes.Remove(req.CIDR)
		_ = s.node.exitRoutes.Save()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTokens manages join tokens.
//
//	GET    /api/tokens
//	POST   /api/tokens {"ttl":"1h", "max_uses":1}
//	DELETE /api/tokens {"prefix":"abc"}
func (s *Scribe) handleTokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		tokens := s.ListTokens()
		if tokens == nil {
			tokens = []JoinToken{}
		}
		_ = json.NewEncoder(w).Encode(tokens)
	case http.MethodPost:
		var req struct {
			TTL     string `json:"ttl"`
			MaxUses int    `json:"max_uses"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}
		var ttl time.Duration
		if req.TTL != "" {
			var err error
			ttl, err = time.ParseDuration(req.TTL)
			if err != nil {
				http.Error(w, `{"error":"invalid TTL"}`, http.StatusBadRequest)
				return
			}
		}
		t := s.CreateToken(ttl, req.MaxUses)
		_ = json.NewEncoder(w).Encode(t)
	case http.MethodDelete:
		var req struct {
			Prefix string `json:"prefix"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Prefix == "" {
			http.Error(w, `{"error":"prefix required"}`, http.StatusBadRequest)
			return
		}
		if err := s.RevokeToken(req.Prefix); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleEventsAPI queries the event log.
//
//	GET /api/events?type=link_up&node=abc&since=2024-01-01T00:00:00Z
func (s *Scribe) handleEventsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.node.events == nil {
		http.Error(w, `{"error":"event log not available"}`, http.StatusServiceUnavailable)
		return
	}
	opts := FilterOpts{
		Type: EventType(r.URL.Query().Get("type")),
		Node: r.URL.Query().Get("node"),
	}
	if since := r.URL.Query().Get("since"); since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			http.Error(w, `{"error":"invalid since"}`, http.StatusBadRequest)
			return
		}
		opts.Since = t
	}
	events, err := ReadFiltered(s.node.events.path, opts)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

// handleVersions returns fleet version distribution.
//
//	GET /api/versions
func (s *Scribe) handleVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peers := s.node.table.Snapshot()
	counts := make(map[string]int)
	var nodes []struct {
		NodeID  string `json:"node_id"`
		Version string `json:"version"`
	}
	for _, p := range peers {
		v := p.Version
		if v == "" {
			v = "unknown"
		}
		counts[v]++
		nodes = append(nodes, struct {
			NodeID  string `json:"node_id"`
			Version string `json:"version"`
		}{p.NodeID, v})
	}
	resp := struct {
		Counts map[string]int `json:"counts"`
		Nodes  interface{}    `json:"nodes"`
	}{counts, nodes}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
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
	s.SetName(req.NodeID, req.Name)
	w.WriteHeader(http.StatusNoContent)
}

// handleMeshIP assigns a manual mesh IP override to a node.
//
//	PUT /api/mesh-ip {"node_id":"...", "mesh_ip":"10.100.1.50"}
func (s *Scribe) handleMeshIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		MeshIP string `json:"mesh_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == "" || req.MeshIP == "" {
		http.Error(w, `{"error":"node_id and mesh_ip required"}`, http.StatusBadRequest)
		return
	}
	if ip := net.ParseIP(req.MeshIP); ip == nil {
		http.Error(w, `{"error":"invalid IP address"}`, http.StatusBadRequest)
		return
	}
	s.SetMeshIP(req.NodeID, req.MeshIP)
	w.WriteHeader(http.StatusNoContent)
}

// handleGroups returns tag-based group counts.
//
//	GET /api/groups
func (s *Scribe) handleGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.Groups())
}

// handleBulk performs a bulk operation on nodes matching a tag pattern.
//
//	POST /api/bulk {"pattern":"site:nyc", "action":"restart"}
//	POST /api/bulk {"pattern":"tag:gw", "action":"config", "config":{"log_level":"debug"}}
//	POST /api/bulk {"pattern":"tag:gw", "action":"push_config"}
func (s *Scribe) handleBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Pattern string            `json:"pattern"`
		Action  string            `json:"action"`
		Config  map[string]string `json:"config,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Pattern == "" || req.Action == "" {
		http.Error(w, `{"error":"pattern and action required"}`, http.StatusBadRequest)
		return
	}

	nodeIDs := s.NodesByTagPattern(req.Pattern)
	if len(nodeIDs) == 0 {
		http.Error(w, `{"error":"no nodes match pattern"}`, http.StatusNotFound)
		return
	}

	var errors []string
	for _, nodeID := range nodeIDs {
		var err error
		switch req.Action {
		case "restart":
			err = s.node.SendRemoteCmd(nodeID, "restart", nil)
		case "config":
			err = s.node.SendRemoteCmd(nodeID, "config", req.Config)
		case "push_config":
			cfg := s.BuildNodeConfigForPeer(nodeID)
			s.PushNodeConfig(nodeID, cfg)
		default:
			http.Error(w, `{"error":"unknown action: `+req.Action+`"}`, http.StatusBadRequest)
			return
		}
		if err != nil {
			errors = append(errors, nodeID+": "+err.Error())
		}
	}

	resp := struct {
		Matched int      `json:"matched"`
		Errors  []string `json:"errors,omitempty"`
	}{
		Matched: len(nodeIDs),
		Errors:  errors,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleTemplates manages config templates.
//
//	GET    /api/templates                                    list templates
//	POST   /api/templates {"pattern":"tag:gw", "config":{}} add/update template
//	DELETE /api/templates {"pattern":"tag:gw"}               delete template
func (s *Scribe) handleTemplates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(s.GetTemplates())

	case http.MethodPost:
		var req struct {
			Pattern string     `json:"pattern"`
			Config  NodeConfig `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Pattern == "" {
			http.Error(w, `{"error":"pattern and config required"}`, http.StatusBadRequest)
			return
		}
		s.SetTemplate(req.Pattern, req.Config)
		w.WriteHeader(http.StatusNoContent)

	case http.MethodDelete:
		var req struct {
			Pattern string `json:"pattern"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Pattern == "" {
			http.Error(w, `{"error":"pattern required"}`, http.StatusBadRequest)
			return
		}
		s.DeleteTemplate(req.Pattern)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleNodeDetail returns detailed information about a single node.
//
//	GET /api/node/<node-id>
func (s *Scribe) handleNodeDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Extract node ID from path: /api/node/<id>
	nodeID := strings.TrimPrefix(r.URL.Path, "/api/node/")
	if nodeID == "" {
		http.Error(w, `{"error":"node_id required in path"}`, http.StatusBadRequest)
		return
	}

	entry, ok := s.node.table.Get(nodeID)
	if !ok {
		http.Error(w, `{"error":"node not found"}`, http.StatusNotFound)
		return
	}

	if entry.MeshIP == "" {
		entry.MeshIP = s.node.meshIPForNode(entry.NodeID).String()
	}

	// Overlay metadata.
	meta := s.node.netCfg.nodeMeta(nodeID)

	// Link info from registry.
	linkType := "none"
	if link, ok := s.node.registry.Get(nodeID); ok && !link.IsClosed() {
		switch {
		case link.ViaNAT:
			linkType = "direct_quic"
		case link.Transport() == "quic":
			linkType = "quic"
		default:
			linkType = "websocket"
		}
	}

	// Stats from scribe.
	var stats *NodeStats
	s.mu.RLock()
	if st, ok := s.stats[nodeID]; ok {
		stats = &st
	}
	s.mu.RUnlock()

	resp := struct {
		NodeID    string     `json:"node_id"`
		Name      string     `json:"name"`
		MeshIP    string     `json:"mesh_ip"`
		Addr      string     `json:"addr"`
		LinkType  string     `json:"link_type"`
		LatencyMS float64    `json:"latency_ms"`
		LossRate  float64    `json:"loss_rate"`
		HopCount  int        `json:"hop_count"`
		Version   string     `json:"version"`
		IsCA      bool       `json:"is_ca"`
		IsScribe  bool       `json:"is_scribe"`
		IsExit    bool       `json:"is_exit"`
		Tags      []string   `json:"tags"`
		LastSeen  string     `json:"last_seen"`
		Stats     *NodeStats `json:"stats,omitempty"`
	}{
		NodeID:    entry.NodeID,
		Name:      meta.Name,
		MeshIP:    entry.MeshIP,
		Addr:      entry.Addr,
		LinkType:  linkType,
		LatencyMS: entry.LatencyMS,
		LossRate:  entry.LossRate,
		HopCount:  entry.HopCount,
		Version:   entry.Version,
		IsCA:      entry.IsCA,
		IsScribe:  entry.IsScribe,
		IsExit:    entry.IsExit,
		Tags:      meta.Tags,
		LastSeen:  entry.LastSeen.Format("2006-01-02T15:04:05Z"),
		Stats:     stats,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Scribe) handleRemoteRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == "" {
		http.Error(w, `{"error":"node_id required"}`, http.StatusBadRequest)
		return
	}
	if err := s.node.SendRemoteCmd(req.NodeID, "restart", nil); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRemoteConfig pushes config changes to a remote node.
//
//	POST /api/remote/config {"node_id":"...", "config":{"log_level":"debug"}}
func (s *Scribe) handleRemoteConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		NodeID string            `json:"node_id"`
		Config map[string]string `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == "" || len(req.Config) == 0 {
		http.Error(w, `{"error":"node_id and config required"}`, http.StatusBadRequest)
		return
	}
	if err := s.node.SendRemoteCmd(req.NodeID, "config", req.Config); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
