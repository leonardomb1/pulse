package node

// SOCKS5 proxy server (RFC 1928).
//
// Routing logic:
//
//   *.pulse domains  →  tunnel through the mesh
//     <nodeID>.pulse:<port>          → localhost:<port> on that node
//     <service>.<nodeID>.pulse:<port>→ <service>:<port> on that node
//
//   All other destinations → check ExitRouteTable for CIDR match.
//     If match  → tunnel through the designated exit node.
//     No match  → dial directly from this machine.
//
// This lets any SOCKS5-aware application (SSH, RDP via tools, browsers,
// database clients) use pulse transparently with zero app changes.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	socks5Ver      = 0x05
	socks5NoAuth   = 0x00
	socks5CmdConn  = 0x01
	socks5AtypIPv4 = 0x01
	socks5AtypFQDN = 0x03
	socks5AtypIPv6 = 0x04
	socks5RespOK   = 0x00
	socks5RespFail = 0x01
)

// SOCKSServer is a SOCKS5 proxy that routes .pulse domains through the mesh
// and other traffic through exit nodes or directly.
type SOCKSServer struct {
	listenAddr string
	router     *Router
	table      *Table
	exitRoutes *ExitRouteTable
	selfID     string
	dnsZones   func() []DNSZone // scribe-distributed zones for CNAME resolution
	traffic    *TrafficCounters
}

func NewSOCKSServer(addr string, router *Router, table *Table, exitRoutes *ExitRouteTable, selfID string, dnsZones func() []DNSZone, tc *TrafficCounters) *SOCKSServer {
	return &SOCKSServer{
		listenAddr: addr,
		router:     router,
		table:      table,
		exitRoutes: exitRoutes,
		selfID:     selfID,
		dnsZones:   dnsZones,
		traffic:    tc,
	}
}

func (s *SOCKSServer) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("socks5 listen %s: %w", s.listenAddr, err)
	}
	Infof("SOCKS5 proxy on %s (.pulse routing enabled)", s.listenAddr)
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
		setTCPOpts(conn)
		go s.handleConn(conn)
	}
}

func (s *SOCKSServer) handleConn(client net.Conn) {
	defer client.Close()

	host, port, err := s.socks5Handshake(client)
	if err != nil {
		Infof("socks5: handshake: %v", err)
		return
	}

	remote, destAddr, _, destNodeID, err := s.resolveDest(host, port)
	if err != nil {
		// Send SOCKS5 general failure reply.
		_, _ = client.Write([]byte{socks5Ver, socks5RespFail, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
		Infof("socks5: resolve %s:%d: %v", host, port, err)
		return
	}

	// Success reply: bound to 0.0.0.0:0.
	_, _ = client.Write([]byte{socks5Ver, socks5RespOK, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})

	if remote == nil {
		// destAddr is a direct TCP address (non-pulse, non-exit-routed).
		target, err := net.Dial("tcp", destAddr)
		if err != nil {
			Infof("socks5: direct dial %s: %v", destAddr, err)
			return
		}
		defer target.Close()
		setTCPOpts(target)
		BridgeDirectCounted(client, target, s.traffic)
		return
	}

	// Route through pulse mesh.
	conn, err := remote.Open()
	if err != nil {
		Infof("socks5: open stream: %v", err)
		return
	}
	defer conn.Close()

	// destNodeID and destAddr are already correctly resolved by resolveDest.
	// For .pulse domains destAddr encodes the in-mesh service address
	// (e.g. "localhost:5432" or "postgres:5432").
	// For exit-routed traffic destAddr is the raw external host:port.
	hdr, _ := json.Marshal(streamMsg{Type: "tunnel", DestNodeID: destNodeID, DestAddr: destAddr})
	_, _ = conn.Write(append(hdr, '\n'))

	BridgeDirectCounted(client, conn, s.traffic)
}

// socks5Handshake performs the RFC 1928 negotiation and returns the requested host:port.
func (s *SOCKSServer) socks5Handshake(conn net.Conn) (host string, port uint16, err error) {
	// Greeting.
	buf := make([]byte, 2)
	if _, err = io.ReadFull(conn, buf); err != nil {
		return
	}
	if buf[0] != socks5Ver {
		err = fmt.Errorf("unsupported SOCKS version %d", buf[0])
		return
	}
	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err = io.ReadFull(conn, methods); err != nil {
		return
	}
	// Accept no-auth only.
	_, _ = conn.Write([]byte{socks5Ver, socks5NoAuth})

	// Request.
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != socks5Ver || hdr[1] != socks5CmdConn {
		err = fmt.Errorf("unsupported command %d", hdr[1])
		return
	}

	switch hdr[3] {
	case socks5AtypIPv4:
		addr := make([]byte, 4)
		if _, err = io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case socks5AtypIPv6:
		addr := make([]byte, 16)
		if _, err = io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case socks5AtypFQDN:
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		fqdn := make([]byte, lenBuf[0])
		if _, err = io.ReadFull(conn, fqdn); err != nil {
			return
		}
		host = string(fqdn)
	default:
		err = fmt.Errorf("unsupported address type %d", hdr[3])
		return
	}

	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(portBuf)
	return
}

// resolveDest determines how to reach host:port.
//
// Returns (session, destAddr, resolvedHost, destNodeID, nil) for mesh-routed connections.
//   - destAddr  — the address the destination node should dial locally (e.g. "localhost:5432")
//   - destNodeID — the NodeID that should terminate the tunnel
//   - resolvedHost — non-empty when CNAME resolution changed the hostname (informational)
//
// Returns (nil, directAddr, "", "", nil) for direct connections (no mesh routing).
func (s *SOCKSServer) resolveDest(host string, port uint16) (session Session, destAddr, resolvedHost, destNodeID string, err error) {
	// .pulse domain → route through the mesh.
	if strings.HasSuffix(host, ".pulse") {
		nodeID := parsePulseNodeID(host)
		if nodeID == "" {
			return nil, "", "", "", fmt.Errorf("cannot parse .pulse domain: %q", host)
		}
		// Fast path: node ID is directly in the routing table.
		if session, err = s.router.Resolve(nodeID); err == nil {
			addr := parsePulseDest(host, port)
			return session, addr, "", nodeID, nil
		}
		// Slow path: the hostname may be a friendly alias (CNAME) distributed
		// via the scribe's DNS zones. Walk the zone table to resolve the chain.
		if s.dnsZones != nil {
			resolved := s.resolvePulseAlias(host, 8)
			if resolved != "" && resolved != host {
				resolvedID := parsePulseNodeID(resolved)
				if session, err = s.router.Resolve(resolvedID); err == nil {
					addr := parsePulseDest(resolved, port)
					return session, addr, resolved, resolvedID, nil
				}
			}
		}
		return nil, "", "", "", fmt.Errorf("no route to .pulse host %q", host)
	}

	// Non-.pulse: check exit route table.
	ip := net.ParseIP(host)
	if ip == nil {
		// Resolve hostname to check exit routes.
		addrs, e := net.LookupHost(host)
		if e == nil && len(addrs) > 0 {
			ip = net.ParseIP(addrs[0])
		}
	}
	if ip != nil {
		if exitNodeID := s.exitRoutes.Lookup(ip); exitNodeID != "" {
			session, err = s.router.Resolve(exitNodeID)
			// destAddr is the external address; the exit node dials it directly.
			destAddr = net.JoinHostPort(host, fmt.Sprint(port))
			destNodeID = exitNodeID
			return
		}
	}

	// Direct dial.
	return nil, net.JoinHostPort(host, fmt.Sprint(port)), "", "", nil
}

// resolvePulseAlias walks the scribe DNS zones following CNAME chains to find
// the terminal .pulse node hostname (one that maps to a real node ID).
// maxDepth prevents infinite loops.
func (s *SOCKSServer) resolvePulseAlias(host string, maxDepth int) string {
	if maxDepth == 0 {
		return ""
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, zone := range s.dnsZones() {
		zoneName := strings.ToLower(strings.TrimSuffix(zone.Name, "."))
		if zoneName != name || zone.Type != "CNAME" {
			continue
		}
		target := strings.ToLower(strings.TrimSuffix(zone.Value, "."))
		// If target is a known node, return it.
		targetID := parsePulseNodeID(target)
		if _, ok := s.table.Get(targetID); ok {
			return target
		}
		// Follow the chain.
		return s.resolvePulseAlias(target, maxDepth-1)
	}
	return ""
}

// parsePulseNodeID extracts the nodeID from a .pulse domain.
//
//	"a3f2c1d4.pulse"          → "a3f2c1d4"
//	"postgres.a3f2c1d4.pulse" → "a3f2c1d4"
func parsePulseNodeID(host string) string {
	host = strings.TrimSuffix(host, ".pulse")
	parts := strings.Split(host, ".")
	return parts[len(parts)-1]
}

// parsePulseDest returns the in-mesh destAddr for a .pulse connection.
//
//	"a3f2c1d4.pulse":5432       → "localhost:5432"
//	"postgres.a3f2c1d4.pulse":0 → "postgres:5432" — service name used as host
func parsePulseDest(host string, port uint16) string {
	h := strings.TrimSuffix(host, ".pulse")
	parts := strings.Split(h, ".")

	portStr := fmt.Sprint(port)
	if len(parts) == 1 {
		return net.JoinHostPort("localhost", portStr)
	}
	return net.JoinHostPort(strings.Join(parts[:len(parts)-1], "."), portStr)
}
