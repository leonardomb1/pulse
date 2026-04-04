package node

// Unix socket control server.
//
// The daemon listens on a Unix domain socket (default ~/.pulse/pulse.sock).
// CLI subcommands connect to this socket and send a single JSON command line;
// the daemon responds with a single JSON result line and closes the connection.
//
// Protocol:
//   → {"cmd":"status"}\n
//   ← {"peers":[...],"stats":{...},"revoked_ids":[...]}\n
//
//   → {"cmd":"dns-list"}\n
//   ← {"zones":[...]}\n
//
//   → {"cmd":"dns-add","zone":{"name":"relay.pulse","type":"CNAME","value":"...","ttl":300}}\n
//   ← {"ok":true}\n
//
//   → {"cmd":"dns-remove","name":"relay.pulse","type":""}\n
//   ← {"ok":true}\n
//
//   → {"cmd":"route-add","cidr":"0.0.0.0/0","via":"d886dd30"}\n
//   ← {"ok":true}\n
//
//   → {"cmd":"route-remove","cidr":"0.0.0.0/0"}\n
//   ← {"ok":true}\n
//
//   → {"cmd":"route-list"}\n
//   ← {"routes":[{"cidr":"...","node_id":"..."}]}\n
//
//   → {"cmd":"revoke","node_id":"..."}\n
//   ← {"ok":true}\n

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ControlServer exposes the node's runtime over a Unix domain socket.
type ControlServer struct {
	socketPath string
	node       *Node
}

func NewControlServer(socketPath string, n *Node) *ControlServer {
	return &ControlServer{socketPath: socketPath, node: n}
}

func (s *ControlServer) ListenAndServe(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0700); err != nil {
		return fmt.Errorf("control: mkdir: %w", err)
	}
	// Check if another daemon is already running by trying to connect.
	// Only remove the socket if it's stale (no one listening).
	if conn, err := net.DialTimeout("unix", s.socketPath, 500*time.Millisecond); err == nil {
		conn.Close()
		return fmt.Errorf("control: another pulse daemon is already running (socket %s is active)", s.socketPath)
	}
	os.Remove(s.socketPath) // remove stale socket from previous run

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("control: listen %s: %w", s.socketPath, err)
	}
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("control: chmod socket: %w", err)
	}

	Infof("control socket: %s", s.socketPath)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go s.handle(conn)
	}
}

type ctrlRequest struct {
	Cmd    string  `json:"cmd"`
	// dns-add
	Zone   DNSZone `json:"zone,omitempty"`
	// dns-remove
	Name   string  `json:"name,omitempty"`
	Type   string  `json:"type,omitempty"`
	// route-add
	CIDR   string  `json:"cidr,omitempty"`
	Via    string  `json:"via,omitempty"`
	// revoke, tag, name
	NodeID string  `json:"node_id,omitempty"`
	// tag-add, tag-remove
	Tag    string  `json:"tag,omitempty"`
	// acl-add
	ACLRule *ACLRule `json:"acl_rule,omitempty"`
	// acl-remove
	Index  int      `json:"index,omitempty"`
	// token-create
	TTL      string `json:"ttl,omitempty"`
	MaxUses  int    `json:"max_uses,omitempty"`
	// token-revoke
	TokenPrefix string `json:"token_prefix,omitempty"`
}

type ctrlResponse struct {
	OK     bool        `json:"ok,omitempty"`
	Error  string      `json:"error,omitempty"`
	Data   interface{} `json:"data,omitempty"`
}

func (s *ControlServer) handle(conn net.Conn) {
	defer conn.Close()

	var req ctrlRequest
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		s.write(conn, ctrlResponse{Error: "bad request: " + err.Error()})
		return
	}

	switch req.Cmd {
	case "status":
		s.cmdStatus(conn)
	case "dns-list":
		s.cmdDNSList(conn)
	case "dns-add":
		s.cmdDNSAdd(conn, req.Zone)
	case "dns-remove":
		s.cmdDNSRemove(conn, req.Name, req.Type)
	case "route-add":
		s.cmdRouteAdd(conn, req.CIDR, req.Via)
	case "route-remove":
		s.cmdRouteRemove(conn, req.CIDR)
	case "route-list":
		s.cmdRouteList(conn)
	case "revoke":
		s.cmdRevoke(conn, req.NodeID)
	case "tag-add":
		s.cmdTagAdd(conn, req.NodeID, req.Tag)
	case "tag-remove":
		s.cmdTagRemove(conn, req.NodeID, req.Tag)
	case "name-set":
		s.cmdNameSet(conn, req.NodeID, req.Name)
	case "acl-list":
		s.cmdACLList(conn)
	case "acl-add":
		s.cmdACLAdd(conn, req.ACLRule)
	case "acl-remove":
		s.cmdACLRemove(conn, req.Index)
	case "token":
		s.cmdToken(conn)
	case "token-create":
		s.cmdTokenCreate(conn, req.TTL, req.MaxUses)
	case "token-list":
		s.cmdTokenList(conn)
	case "token-revoke":
		s.cmdTokenRevoke(conn, req.TokenPrefix)
	case "stop":
		s.write(conn, ctrlResponse{OK: true})
		s.node.Stop()
	default:
		s.write(conn, ctrlResponse{Error: "unknown command: " + req.Cmd})
	}
}

func (s *ControlServer) cmdStatus(conn net.Conn) {
	peers := s.node.table.Snapshot()
	meta := s.node.netCfg.allNodeMeta()
	for i := range peers {
		if peers[i].MeshIP == "" {
			peers[i].MeshIP = MeshIPFromNodeID(peers[i].NodeID).String()
		}
		// Overlay scribe-managed metadata.
		if m, ok := meta[peers[i].NodeID]; ok {
			peers[i].Name = m.Name
			peers[i].Tags = m.Tags
		}
	}
	s.write(conn, map[string]interface{}{
		"self":       s.node.id,
		"peers":      peers,
		"network_id": s.node.cfg.Node.NetworkID,
		"mesh_cidr":  s.node.cfg.Tun.CIDR,
	})
}

func (s *ControlServer) cmdDNSList(conn net.Conn) {
	zones := s.node.netCfg.dnsZones()
	if zones == nil {
		zones = []DNSZone{}
	}
	s.write(conn, map[string]interface{}{"zones": zones})
}

func (s *ControlServer) cmdDNSAdd(conn net.Conn, zone DNSZone) {
	if s.node.scribe == nil {
		s.write(conn, ctrlResponse{Error: "this node is not the scribe"})
		return
	}
	if err := s.node.scribe.AddDNSZone(context.Background(), zone); err != nil {
		s.write(conn, ctrlResponse{Error: err.Error()})
		return
	}
	s.write(conn, ctrlResponse{OK: true})
}

func (s *ControlServer) cmdDNSRemove(conn net.Conn, name, recType string) {
	if s.node.scribe == nil {
		s.write(conn, ctrlResponse{Error: "this node is not the scribe"})
		return
	}
	if err := s.node.scribe.RemoveDNSZone(context.Background(), name, recType); err != nil {
		s.write(conn, ctrlResponse{Error: err.Error()})
		return
	}
	s.write(conn, ctrlResponse{OK: true})
}

func (s *ControlServer) cmdRouteAdd(conn net.Conn, cidr, via string) {
	if cidr == "" || via == "" {
		s.write(conn, ctrlResponse{Error: "cidr and via are required"})
		return
	}
	if err := s.node.exitRoutes.Add(cidr, via); err != nil {
		s.write(conn, ctrlResponse{Error: err.Error()})
		return
	}
	s.node.exitRoutes.Save()
	s.write(conn, ctrlResponse{OK: true})
}

func (s *ControlServer) cmdRouteRemove(conn net.Conn, cidr string) {
	if cidr == "" {
		s.write(conn, ctrlResponse{Error: "cidr is required"})
		return
	}
	s.node.exitRoutes.Remove(cidr)
	s.node.exitRoutes.Save()
	s.write(conn, ctrlResponse{OK: true})
}

func (s *ControlServer) cmdRouteList(conn net.Conn) {
	routes := s.node.exitRoutes.Snapshot()
	s.write(conn, map[string]interface{}{"routes": routes})
}

func (s *ControlServer) cmdRevoke(conn net.Conn, nodeID string) {
	if nodeID == "" {
		s.write(conn, ctrlResponse{Error: "node_id is required"})
		return
	}
	if s.node.scribe == nil {
		s.write(conn, ctrlResponse{Error: "this node is not the scribe"})
		return
	}
	s.node.scribe.Revoke(context.Background(), nodeID)
	s.write(conn, ctrlResponse{OK: true})
}

func (s *ControlServer) cmdToken(conn net.Conn) {
	if s.node.ca == nil {
		s.write(conn, ctrlResponse{Error: "this node is not the CA"})
		return
	}
	s.write(conn, map[string]interface{}{"token": s.node.ca.JoinToken})
}

func (s *ControlServer) cmdTokenCreate(conn net.Conn, ttlStr string, maxUses int) {
	if s.node.scribe == nil {
		s.write(conn, ctrlResponse{Error: "this node is not the scribe"})
		return
	}
	var ttl time.Duration
	if ttlStr != "" {
		var err error
		ttl, err = time.ParseDuration(ttlStr)
		if err != nil {
			s.write(conn, ctrlResponse{Error: "invalid TTL: " + err.Error()})
			return
		}
	}
	t := s.node.scribe.CreateToken(context.Background(), ttl, maxUses)
	s.write(conn, map[string]interface{}{"token": t})
}

func (s *ControlServer) cmdTokenList(conn net.Conn) {
	if s.node.scribe == nil {
		s.write(conn, ctrlResponse{Error: "this node is not the scribe"})
		return
	}
	tokens := s.node.scribe.ListTokens()
	if tokens == nil {
		tokens = []JoinToken{}
	}
	s.write(conn, map[string]interface{}{"tokens": tokens})
}

func (s *ControlServer) cmdTokenRevoke(conn net.Conn, prefix string) {
	if s.node.scribe == nil {
		s.write(conn, ctrlResponse{Error: "this node is not the scribe"})
		return
	}
	if prefix == "" {
		s.write(conn, ctrlResponse{Error: "token_prefix is required"})
		return
	}
	if err := s.node.scribe.RevokeToken(context.Background(), prefix); err != nil {
		s.write(conn, ctrlResponse{Error: err.Error()})
		return
	}
	s.write(conn, ctrlResponse{OK: true})
}

func (s *ControlServer) cmdACLList(conn net.Conn) {
	// Return global ACL rules from the network config.
	var rules []ACLRule
	if s.node.scribe != nil {
		rules = s.node.scribe.GlobalACLRules()
	} else if snc := s.node.netCfg.get(); snc != nil && len(snc.Config.GlobalACLs) > 0 {
		rules = snc.Config.GlobalACLs[0].Allow
	}
	if rules == nil {
		rules = []ACLRule{}
	}
	s.write(conn, map[string]interface{}{"rules": rules})
}

func (s *ControlServer) cmdACLAdd(conn net.Conn, rule *ACLRule) {
	if rule == nil {
		s.write(conn, ctrlResponse{Error: "acl_rule is required"})
		return
	}
	if s.node.scribe == nil {
		s.write(conn, ctrlResponse{Error: "this node is not the scribe"})
		return
	}
	s.node.scribe.AddACLRule(context.Background(), *rule)
	s.write(conn, ctrlResponse{OK: true})
}

func (s *ControlServer) cmdACLRemove(conn net.Conn, index int) {
	if s.node.scribe == nil {
		s.write(conn, ctrlResponse{Error: "this node is not the scribe"})
		return
	}
	if err := s.node.scribe.RemoveACLRule(context.Background(), index); err != nil {
		s.write(conn, ctrlResponse{Error: err.Error()})
		return
	}
	s.write(conn, ctrlResponse{OK: true})
}

func (s *ControlServer) cmdTagAdd(conn net.Conn, nodeID, tag string) {
	if nodeID == "" || tag == "" {
		s.write(conn, ctrlResponse{Error: "node_id and tag are required"})
		return
	}
	if s.node.scribe == nil {
		s.write(conn, ctrlResponse{Error: "this node is not the scribe"})
		return
	}
	s.node.scribe.SetTag(context.Background(), nodeID, tag)
	s.write(conn, ctrlResponse{OK: true})
}

func (s *ControlServer) cmdTagRemove(conn net.Conn, nodeID, tag string) {
	if nodeID == "" || tag == "" {
		s.write(conn, ctrlResponse{Error: "node_id and tag are required"})
		return
	}
	if s.node.scribe == nil {
		s.write(conn, ctrlResponse{Error: "this node is not the scribe"})
		return
	}
	s.node.scribe.RemoveTag(context.Background(), nodeID, tag)
	s.write(conn, ctrlResponse{OK: true})
}

func (s *ControlServer) cmdNameSet(conn net.Conn, nodeID, name string) {
	if nodeID == "" {
		s.write(conn, ctrlResponse{Error: "node_id is required"})
		return
	}
	if s.node.scribe == nil {
		s.write(conn, ctrlResponse{Error: "this node is not the scribe"})
		return
	}
	s.node.scribe.SetName(context.Background(), nodeID, name)
	s.write(conn, ctrlResponse{OK: true})
}

func (s *ControlServer) write(conn net.Conn, v interface{}) {
	b, _ := json.Marshal(v)
	b = append(b, '\n')
	conn.Write(b)
}
