package node

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
)

// CIDRRoute maps a network prefix to an exit relay node.
// Traffic destined for IPs in CIDR is tunnelled through NodeID.
type CIDRRoute struct {
	CIDR      string `json:"cidr"`
	NodeID    string `json:"node_id"`
	AutoLearn bool   `json:"auto,omitempty"` // true if learned from gossip, false if manually added
	net       *net.IPNet
}

// ExitRouteTable is the client-side CIDR → exit node mapping.
// Persisted as JSON to disk so it survives restarts.
type ExitRouteTable struct {
	mu     sync.RWMutex
	routes []CIDRRoute
	path   string
}

func NewExitRouteTable(path string) *ExitRouteTable {
	return &ExitRouteTable{path: path}
}

// Load reads routes from disk. No-op if the file doesn't exist yet.
func (t *ExitRouteTable) Load() error {
	data, err := os.ReadFile(t.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var routes []CIDRRoute
	if err := json.Unmarshal(data, &routes); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range routes {
		_, ipnet, err := net.ParseCIDR(routes[i].CIDR)
		if err != nil {
			continue
		}
		routes[i].net = ipnet
	}
	t.routes = routes
	return nil
}

// Save persists the current route table to disk atomically.
func (t *ExitRouteTable) Save() error {
	t.mu.RLock()
	data, err := json.MarshalIndent(t.routes, "", "  ")
	t.mu.RUnlock()
	if err != nil {
		return err
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, t.path)
}

// Add inserts a CIDR → nodeID mapping (or updates existing).
func (t *ExitRouteTable) Add(cidr, nodeID string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, r := range t.routes {
		if r.CIDR == cidr {
			t.routes[i].NodeID = nodeID
			t.routes[i].net = ipnet
			return nil
		}
	}
	t.routes = append(t.routes, CIDRRoute{CIDR: cidr, NodeID: nodeID, net: ipnet})
	return nil
}

// Remove deletes the route for cidr.
func (t *ExitRouteTable) Remove(cidr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.routes[:0]
	for _, r := range t.routes {
		if r.CIDR != cidr {
			out = append(out, r)
		}
	}
	t.routes = out
}

// Lookup returns the exit node ID for ip using longest-prefix match.
// Returns empty string if no route matches.
func (t *ExitRouteTable) Lookup(ip net.IP) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var bestNode string
	var bestOnes = -1
	for _, r := range t.routes {
		if r.net != nil && r.net.Contains(ip) {
			ones, _ := r.net.Mask.Size()
			if ones > bestOnes {
				bestOnes = ones
				bestNode = r.NodeID
			}
		}
	}
	return bestNode
}

// SyncFromGossip updates auto-learned routes from exit nodes in the gossip table.
// Manual routes are never touched. Auto-learned routes for nodes no longer
// advertising a CIDR are removed.
func (t *ExitRouteTable) SyncFromGossip(exitNodes []PeerEntry) {
	// Build the desired set of auto-learned routes.
	want := make(map[string]string) // CIDR → nodeID
	for _, e := range exitNodes {
		for _, cidr := range e.ExitCIDRs {
			want[cidr] = e.NodeID
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Remove stale auto-learned routes.
	out := t.routes[:0]
	for _, r := range t.routes {
		if r.AutoLearn {
			if nodeID, ok := want[r.CIDR]; ok && nodeID == r.NodeID {
				out = append(out, r) // still wanted
				delete(want, r.CIDR) // already have it
			}
			// else: stale, drop it
		} else {
			out = append(out, r) // manual route, keep
		}
	}

	// Add new auto-learned routes.
	for cidr, nodeID := range want {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		out = append(out, CIDRRoute{CIDR: cidr, NodeID: nodeID, AutoLearn: true, net: ipnet})
	}
	t.routes = out
}

// Snapshot returns a copy of the current route table for display.
func (t *ExitRouteTable) Snapshot() []CIDRRoute {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]CIDRRoute, len(t.routes))
	copy(out, t.routes)
	return out
}
