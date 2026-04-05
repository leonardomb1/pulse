package node

import (
	"encoding/json"
	"maps"
	"net/http"
)

func (s *Scribe) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peers := s.node.table.Snapshot()
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
	_ = json.NewEncoder(w).Encode(routes)
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
