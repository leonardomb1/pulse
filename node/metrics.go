package node

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// handleMetrics serves Prometheus-format metrics.
//
//	GET /metrics
//
// Metrics exposed:
//
//	pulse_peers_total                       - total known peers
//	pulse_peers_connected                   - peers with active sessions
//	pulse_peer_latency_ms{node_id,name}     - per-peer latency
//	pulse_peer_loss_ratio{node_id,name}     - per-peer packet loss (0-1)
//	pulse_peer_hop_count{node_id,name}      - per-peer hop count
//	pulse_revoked_nodes_total               - revoked node count
//	pulse_dns_zones_total                   - DNS zone count
//	pulse_acl_rules_total                   - ACL rule count
//	pulse_tokens_total                      - managed token count
//	pulse_tokens_valid                      - valid (non-expired, non-exhausted) tokens
//	pulse_node_info{node_id,network_id}     - constant 1, labels carry metadata
//	pulse_cert_expiry_seconds               - seconds until node cert expires
//	pulse_node_stats_bytes_in{node_id}      - reported bytes in
//	pulse_node_stats_bytes_out{node_id}     - reported bytes out
//	pulse_node_stats_active_conns{node_id}  - reported active connections
func (s *Scribe) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var b strings.Builder

	peers := s.node.table.Snapshot()
	connected := s.node.registry.All()
	connSet := make(map[string]bool, len(connected))
	for _, l := range connected {
		connSet[l.NodeID] = true
	}

	// Peer counts.
	fmt.Fprintf(&b, "# HELP pulse_peers_total Total known peers in gossip table.\n")
	fmt.Fprintf(&b, "# TYPE pulse_peers_total gauge\n")
	fmt.Fprintf(&b, "pulse_peers_total %d\n", len(peers))

	fmt.Fprintf(&b, "# HELP pulse_peers_connected Peers with active sessions.\n")
	fmt.Fprintf(&b, "# TYPE pulse_peers_connected gauge\n")
	fmt.Fprintf(&b, "pulse_peers_connected %d\n", len(connected))

	// Per-peer metrics.
	fmt.Fprintf(&b, "# HELP pulse_peer_latency_ms Measured RTT to peer in milliseconds.\n")
	fmt.Fprintf(&b, "# TYPE pulse_peer_latency_ms gauge\n")
	fmt.Fprintf(&b, "# HELP pulse_peer_loss_ratio Packet loss ratio to peer (0-1).\n")
	fmt.Fprintf(&b, "# TYPE pulse_peer_loss_ratio gauge\n")
	fmt.Fprintf(&b, "# HELP pulse_peer_hop_count Hop count to peer.\n")
	fmt.Fprintf(&b, "# TYPE pulse_peer_hop_count gauge\n")
	for _, p := range peers {
		if p.NodeID == s.node.id {
			continue
		}
		name := p.Name
		if name == "" {
			name = p.NodeID[:8]
		}
		labels := fmt.Sprintf(`node_id=%q,name=%q`, p.NodeID, name)
		if p.LatencyMS > 0 && p.LatencyMS < 1e15 {
			fmt.Fprintf(&b, "pulse_peer_latency_ms{%s} %.2f\n", labels, p.LatencyMS)
		}
		fmt.Fprintf(&b, "pulse_peer_loss_ratio{%s} %.4f\n", labels, p.LossRate)
		fmt.Fprintf(&b, "pulse_peer_hop_count{%s} %d\n", labels, p.HopCount)
	}

	// Per-peer link type: "nat", "quic", "websocket", or "none".
	fmt.Fprintf(&b, "# HELP pulse_peer_link_type Active link type to peer (label).\n")
	fmt.Fprintf(&b, "# TYPE pulse_peer_link_type gauge\n")
	for _, p := range peers {
		if p.NodeID == s.node.id {
			continue
		}
		name := p.Name
		if name == "" {
			name = p.NodeID[:8]
		}
		linkType := "none"
		if link, ok := s.node.registry.Get(p.NodeID); ok && !link.IsClosed() {
			switch {
			case link.ViaNAT:
				linkType = "nat"
			case link.Transport() == "quic":
				linkType = "quic"
			default:
				linkType = "websocket"
			}
		}
		fmt.Fprintf(&b, "pulse_peer_link_type{node_id=%q,name=%q,type=%q} 1\n", p.NodeID, name, linkType)
	}

	// Node info (constant 1, labels carry metadata).
	fmt.Fprintf(&b, "# HELP pulse_node_info Node metadata.\n")
	fmt.Fprintf(&b, "# TYPE pulse_node_info gauge\n")
	fmt.Fprintf(&b, "pulse_node_info{node_id=%q,network_id=%q} 1\n",
		s.node.id, s.node.cfg.Node.NetworkID)

	// Cert expiry.
	if len(s.node.identity.TLSCert.Certificate) > 0 {
		if leaf, err := parseLeafCert(s.node.identity.TLSCert); err == nil {
			remaining := time.Until(leaf.NotAfter).Seconds()
			fmt.Fprintf(&b, "# HELP pulse_cert_expiry_seconds Seconds until node cert expires.\n")
			fmt.Fprintf(&b, "# TYPE pulse_cert_expiry_seconds gauge\n")
			fmt.Fprintf(&b, "pulse_cert_expiry_seconds %.0f\n", remaining)
		}
	}

	// Scribe-specific metrics.
	s.mu.RLock()
	revokedCount := len(s.revokedIDs)
	dnsCount := len(s.dnsZones)
	aclCount := 0
	if len(s.globalACLs) > 0 {
		aclCount = len(s.globalACLs[0].Allow)
	}
	tokenTotal := len(s.tokens)
	tokenValid := 0
	for _, t := range s.tokens {
		if t.IsValid() {
			tokenValid++
		}
	}

	// Node stats from peers.
	stats := make(map[string]NodeStats, len(s.stats))
	for k, v := range s.stats {
		stats[k] = v
	}
	s.mu.RUnlock()

	fmt.Fprintf(&b, "# HELP pulse_revoked_nodes_total Number of revoked nodes.\n")
	fmt.Fprintf(&b, "# TYPE pulse_revoked_nodes_total gauge\n")
	fmt.Fprintf(&b, "pulse_revoked_nodes_total %d\n", revokedCount)

	fmt.Fprintf(&b, "# HELP pulse_dns_zones_total Number of DNS zones.\n")
	fmt.Fprintf(&b, "# TYPE pulse_dns_zones_total gauge\n")
	fmt.Fprintf(&b, "pulse_dns_zones_total %d\n", dnsCount)

	fmt.Fprintf(&b, "# HELP pulse_acl_rules_total Number of ACL rules.\n")
	fmt.Fprintf(&b, "# TYPE pulse_acl_rules_total gauge\n")
	fmt.Fprintf(&b, "pulse_acl_rules_total %d\n", aclCount)

	fmt.Fprintf(&b, "# HELP pulse_tokens_total Total managed tokens.\n")
	fmt.Fprintf(&b, "# TYPE pulse_tokens_total gauge\n")
	fmt.Fprintf(&b, "pulse_tokens_total %d\n", tokenTotal)

	fmt.Fprintf(&b, "# HELP pulse_tokens_valid Valid (usable) tokens.\n")
	fmt.Fprintf(&b, "# TYPE pulse_tokens_valid gauge\n")
	fmt.Fprintf(&b, "pulse_tokens_valid %d\n", tokenValid)

	// Per-node stats.
	if len(stats) > 0 {
		fmt.Fprintf(&b, "# HELP pulse_node_stats_bytes_in Bytes received by node.\n")
		fmt.Fprintf(&b, "# TYPE pulse_node_stats_bytes_in gauge\n")
		fmt.Fprintf(&b, "# HELP pulse_node_stats_bytes_out Bytes sent by node.\n")
		fmt.Fprintf(&b, "# TYPE pulse_node_stats_bytes_out gauge\n")
		fmt.Fprintf(&b, "# HELP pulse_node_stats_active_conns Active connections on node.\n")
		fmt.Fprintf(&b, "# TYPE pulse_node_stats_active_conns gauge\n")
		for _, st := range stats {
			labels := fmt.Sprintf(`node_id=%q`, st.NodeID)
			fmt.Fprintf(&b, "pulse_node_stats_bytes_in{%s} %d\n", labels, st.BytesIn)
			fmt.Fprintf(&b, "pulse_node_stats_bytes_out{%s} %d\n", labels, st.BytesOut)
			fmt.Fprintf(&b, "pulse_node_stats_active_conns{%s} %d\n", labels, st.ActiveConns)
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

// parseLeafCert extracts the leaf x509 certificate from a tls.Certificate.
func parseLeafCert(tlsCert tls.Certificate) (*x509.Certificate, error) {
	if len(tlsCert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate")
	}
	return x509.ParseCertificate(tlsCert.Certificate[0])
}
