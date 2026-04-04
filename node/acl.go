package node

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// PortRange is an inclusive range of TCP ports.
type PortRange struct {
	Low  uint16 `json:"low"`
	High uint16 `json:"high"` // 0 means same as Low (single port)
}

func (r PortRange) Contains(port uint16) bool {
	hi := r.High
	if hi == 0 {
		hi = r.Low
	}
	return port >= r.Low && port <= hi
}

// ParsePortRanges parses a comma-separated list like "22,80,443,8000-9000".
func ParsePortRanges(s string) ([]PortRange, error) {
	if s == "" {
		return nil, nil
	}
	var out []PortRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			low, err := strconv.ParseUint(lo, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("bad port %q", lo)
			}
			high, err := strconv.ParseUint(hi, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("bad port %q", hi)
			}
			out = append(out, PortRange{Low: uint16(low), High: uint16(high)})
		} else {
			p, err := strconv.ParseUint(part, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("bad port %q", part)
			}
			out = append(out, PortRange{Low: uint16(p)})
		}
	}
	return out, nil
}

// FormatPortRanges formats port ranges as a human-readable string.
func FormatPortRanges(ports []PortRange) string {
	if len(ports) == 0 {
		return "*"
	}
	var parts []string
	for _, pr := range ports {
		if pr.High == 0 || pr.High == pr.Low {
			parts = append(parts, fmt.Sprint(pr.Low))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", pr.Low, pr.High))
		}
	}
	return strings.Join(parts, ",")
}

// ACLRule defines a traffic policy. Rules are evaluated top-to-bottom; first match wins.
type ACLRule struct {
	Action     string      `json:"action"`            // "allow" or "deny" (default "allow")
	SrcPattern string      `json:"src_pat,omitempty"` // source node pattern (glob, tag:xxx, or name)
	DstPattern string      `json:"dst_pat"`           // destination node pattern
	Ports      []PortRange `json:"ports,omitempty"`   // empty = all ports
}

// action returns the effective action, defaulting to "allow" for backward compat.
func (r ACLRule) action() string {
	if r.Action == "" {
		return "allow"
	}
	return r.Action
}

// MetaLookup resolves a nodeID to its operator-assigned metadata.
type MetaLookup func(nodeID string) NodeMeta

// matchesNode checks if pattern matches nodeID, considering tags and names.
// Pattern formats:
//   - "*" or glob: matched against nodeID
//   - "tag:<name>": true if the node has that tag
//   - plain string that isn't a glob: matched as name first, then as nodeID glob
func MatchesNode(pattern, nodeID string, meta NodeMeta) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	// Tag match: "tag:prod"
	if after, ok := strings.CutPrefix(pattern, "tag:"); ok {
		return slices.Contains(meta.Tags, after)
	}
	// Name match (exact)
	if meta.Name != "" && pattern == meta.Name {
		return true
	}
	// Glob match on nodeID
	ok, _ := path.Match(pattern, nodeID)
	return ok
}

func (r ACLRule) matches(srcNodeID, dstNodeID string, port uint16, lookup MetaLookup) bool {
	// Check source pattern
	if r.SrcPattern != "" && r.SrcPattern != "*" {
		srcMeta := NodeMeta{}
		if lookup != nil {
			srcMeta = lookup(srcNodeID)
		}
		if !MatchesNode(r.SrcPattern, srcNodeID, srcMeta) {
			return false
		}
	}
	// Check destination pattern
	dstMeta := NodeMeta{}
	if lookup != nil {
		dstMeta = lookup(dstNodeID)
	}
	if !MatchesNode(r.DstPattern, dstNodeID, dstMeta) {
		return false
	}
	// Check ports
	if len(r.Ports) == 0 {
		return true
	}
	for _, pr := range r.Ports {
		if pr.Contains(port) {
			return true
		}
	}
	return false
}

// NodeACL is the policy for one node. Rules are evaluated in order; first match wins.
type NodeACL struct {
	NodeID  string    `json:"node_id"`
	Allow   []ACLRule `json:"allow"` // kept as "allow" in JSON for backward compat, but rules can be deny
	Version int64     `json:"version"`
}

// Check returns nil if srcNodeID may connect to destNodeID:port.
// Uses first-match evaluation. No rules = allow-all (open by default).
// Any rules present + no match = implicit deny.
func (a NodeACL) Check(srcNodeID, destNodeID string, port uint16, lookup MetaLookup) error {
	if len(a.Allow) == 0 {
		return nil // open by default when no rules defined
	}
	for _, rule := range a.Allow {
		if rule.matches(srcNodeID, destNodeID, port, lookup) {
			if rule.action() == "deny" {
				return fmt.Errorf("acl: %s → %s:%d denied (explicit deny)", srcNodeID, destNodeID, port)
			}
			return nil
		}
	}
	return fmt.Errorf("acl: %s → %s:%d denied (no matching rule)", srcNodeID, destNodeID, port)
}

// ACLTable is a concurrent-safe store of node ACL policies.
type ACLTable struct {
	mu      sync.RWMutex
	entries map[string]NodeACL
}

func NewACLTable() *ACLTable {
	return &ACLTable{entries: make(map[string]NodeACL)}
}

// Upsert adds or replaces an entry (keeps the higher Version).
func (t *ACLTable) Upsert(a NodeACL) {
	t.mu.Lock()
	defer t.mu.Unlock()
	existing, ok := t.entries[a.NodeID]
	if !ok || a.Version >= existing.Version {
		t.entries[a.NodeID] = a
	}
}

// Get returns the ACL for a node. If no explicit ACL exists, returns a
// default allow-all policy so nodes without ACLs are unrestricted.
func (t *ACLTable) Get(nodeID string) NodeACL {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if acl, ok := t.entries[nodeID]; ok {
		return acl
	}
	return NodeACL{NodeID: nodeID}
}

// Check is a convenience method on the table.
func (t *ACLTable) Check(callerID, destNodeID string, port uint16, lookup MetaLookup) error {
	return t.Get(callerID).Check(callerID, destNodeID, port, lookup)
}

// MergeFrom merges a slice of ACLs received via gossip.
func (t *ACLTable) MergeFrom(acls []NodeACL) {
	for _, a := range acls {
		t.Upsert(a)
	}
}

// Snapshot returns a copy of all ACL entries.
func (t *ACLTable) Snapshot() []NodeACL {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]NodeACL, 0, len(t.entries))
	for _, a := range t.entries {
		out = append(out, a)
	}
	return out
}

// portFromAddr extracts the numeric port from "host:port".
func portFromAddr(addr string) uint16 {
	parts := strings.SplitN(addr, ":", 2)
	if len(parts) != 2 {
		return 0
	}
	p, _ := strconv.ParseUint(parts[1], 10, 16)
	return uint16(p)
}
