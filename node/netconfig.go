package node

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync"
)

// DNSZone is a DNS record pushed by the scribe to all node DNS servers.
type DNSZone struct {
	Name  string `json:"name"`  // fully-qualified record name, e.g. "svc.internal.example.com."
	Type  string `json:"type"`  // A, AAAA, CNAME, TXT, SRV
	Value string `json:"value"` // record value
	TTL   uint32 `json:"ttl"`
}

// NodeMeta holds operator-assigned metadata for a node (name, tags).
// Managed by the scribe and distributed via NetworkConfig.
type NodeMeta struct {
	Name   string   `json:"name,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	MeshIP string   `json:"mesh_ip,omitempty"` // operator-assigned mesh IP override
}

// NetworkConfig is the authoritative network-wide configuration distributed by
// the scribe node. Nodes merge by keeping the entry with the highest Version.
type NetworkConfig struct {
	Version    int64               `json:"version"`               // monotonically increasing (unix milliseconds)
	MeshCIDR   string              `json:"mesh_cidr,omitempty"`   // network-wide mesh IP range (e.g. "10.100.0.0/16")
	RevokedIDs []string            `json:"revoked_ids"`           // node IDs whose certificates have been revoked
	DNSZones   []DNSZone           `json:"dns_zones"`             // additional DNS records served by all nodes
	GlobalACLs []NodeACL           `json:"global_acls"`           // network-wide ACL additions
	NodeMeta   map[string]NodeMeta `json:"node_meta,omitempty"`   // operator-assigned node names and tags
	JoinTokens []JoinToken         `json:"join_tokens,omitempty"` // scribe-managed join tokens
}

// SignedNetConfig wraps a NetworkConfig with an ed25519 signature from the scribe.
// Nodes verify the signature against the scribe's public key from the gossip table
// before accepting a new config.
type SignedNetConfig struct {
	Config    NetworkConfig `json:"config"`
	Signature []byte        `json:"sig"`
	ScribeID  string        `json:"scribe_id"`
}

// SignNetConfig signs cfg with the scribe's private key.
func SignNetConfig(cfg NetworkConfig, priv ed25519.PrivateKey, scribeID string) (SignedNetConfig, error) {
	payload, err := json.Marshal(cfg)
	if err != nil {
		return SignedNetConfig{}, err
	}
	sig := ed25519.Sign(priv, payload)
	return SignedNetConfig{Config: cfg, Signature: sig, ScribeID: scribeID}, nil
}

// VerifyNetConfig checks the signature on a SignedNetConfig against pub.
func VerifyNetConfig(snc SignedNetConfig, pub ed25519.PublicKey) error {
	payload, err := json.Marshal(snc.Config)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, snc.Signature) {
		return fmt.Errorf("netconfig: invalid signature from scribe %s", snc.ScribeID)
	}
	return nil
}

// NodeConfig is the per-node configuration managed by the scribe.
// Nodes receive this via mesh from the scribe
// and persist it to state.dat.
type NodeConfig struct {
	Version      int64    `json:"version"`
	TunEnabled   bool     `json:"tun_enabled"`
	SocksEnabled bool     `json:"socks_enabled"`
	DNSEnabled   bool     `json:"dns_enabled"`
	ExitEnabled  bool     `json:"exit_enabled"`
	ExitCIDRs    []string `json:"exit_cidrs,omitempty"`
	FECEnabled   bool     `json:"fec_enabled"`
	MeshIP       string   `json:"mesh_ip,omitempty"`
	MeshCIDR     string   `json:"mesh_cidr,omitempty"`
	LogLevel     string   `json:"log_level,omitempty"`
}

// SignedNodeConfig wraps a NodeConfig with a scribe signature.
type SignedNodeConfig struct {
	Config    NodeConfig `json:"config"`
	Signature []byte     `json:"sig"`
	ScribeID  string     `json:"scribe_id"`
}

// SignNodeConfig signs a per-node config with the scribe's private key.
func SignNodeConfig(cfg NodeConfig, priv ed25519.PrivateKey, scribeID string) (SignedNodeConfig, error) {
	payload, err := json.Marshal(cfg)
	if err != nil {
		return SignedNodeConfig{}, err
	}
	sig := ed25519.Sign(priv, payload)
	return SignedNodeConfig{Config: cfg, Signature: sig, ScribeID: scribeID}, nil
}

// VerifyNodeConfig checks the signature on a SignedNodeConfig.
func VerifyNodeConfig(snc SignedNodeConfig, pub ed25519.PublicKey) error {
	payload, err := json.Marshal(snc.Config)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, snc.Signature) {
		return fmt.Errorf("nodeconfig: invalid signature from scribe %s", snc.ScribeID)
	}
	return nil
}

// nodeStateStore is the node-local store for signed per-node config from the scribe.
type nodeStateStore struct {
	mu      sync.RWMutex
	current *SignedNodeConfig
}

func (s *nodeStateStore) get() *SignedNodeConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

func (s *nodeStateStore) merge(snc SignedNodeConfig) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil || snc.Config.Version > s.current.Config.Version {
		s.current = &snc
		return true
	}
	return false
}

// netConfigStore is the node-local store for the current signed network config.
// It is updated atomically when a higher-versioned config is received.
type netConfigStore struct {
	mu      sync.RWMutex
	current *SignedNetConfig
}

func (s *netConfigStore) get() *SignedNetConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// merge replaces the stored config if snc has a higher version.
// Returns true if the config was updated.
func (s *netConfigStore) merge(snc SignedNetConfig) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil || snc.Config.Version > s.current.Config.Version {
		s.current = &snc
		return true
	}
	return false
}

// isRevoked reports whether nodeID appears in the current revocation list.
func (s *netConfigStore) isRevoked(nodeID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return false
	}
	for _, id := range s.current.Config.RevokedIDs {
		if id == nodeID {
			return true
		}
	}
	return false
}

// nodeMeta returns the metadata for a specific node from the active NetworkConfig.
func (s *netConfigStore) nodeMeta(nodeID string) NodeMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return NodeMeta{}
	}
	return s.current.Config.NodeMeta[nodeID]
}

// allNodeMeta returns all node metadata from the active NetworkConfig.
func (s *netConfigStore) allNodeMeta() map[string]NodeMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return nil
	}
	return s.current.Config.NodeMeta
}

// dnsZones returns the current extra DNS zones from the active NetworkConfig.
func (s *netConfigStore) dnsZones() []DNSZone {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return nil
	}
	return s.current.Config.DNSZones
}
