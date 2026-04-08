package node

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

// TunnelRequest describes where to route a stream.
type TunnelRequest struct {
	DestNodeID string `json:"dest_node"`
	DestAddr   string `json:"dest_addr"`
}

// ServeTCP listens for inbound TCP client connections and relays them.
// Uses SO_REUSEPORT so the kernel can load-balance across multiple goroutines.
func ServeTCP(listenAddr string, router *Router, selfID string, isRevoked func(string) bool, tc *TrafficCounters) error {
	ln, err := reusePortListen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("tcp listen %s: %w", listenAddr, err)
	}
	Infof("TCP tunnel listener on %s (SO_REUSEPORT)", listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		// TCP_NODELAY: critical for SSH/RDP — prevents Nagle's algorithm from
		// batching small writes and adding up to 200ms of artificial latency.
		setTCPOpts(conn)
		go handleClientConn(conn, router, selfID, isRevoked, tc)
	}
}

func handleClientConn(client net.Conn, router *Router, selfID string, isRevoked func(string) bool, tc *TrafficCounters) {
	defer func() { _ = client.Close() }()

	reader := bufio.NewReader(client)
	line, err := reader.ReadString('\n')
	if err != nil {
		Infof("tunnel: read header: %v", err)
		return
	}

	var req TunnelRequest
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		Warnf("tunnel: bad header: %v", err)
		return
	}

	if req.DestNodeID == selfID || req.DestNodeID == "" {
		// Local client connections aren't caller-identified; skip ACL for local.
		target, err := dialTarget(req.DestAddr)
		if err != nil {
			Infof("tunnel: local dial %s: %v", req.DestAddr, err)
			return
		}
		defer func() { _ = target.Close() }()
		Infof("tunnel: local → %s", req.DestAddr)
		bridgeCounted(reader, client, target, tc)
		return
	}

	if isRevoked != nil && isRevoked(req.DestNodeID) {
		Warnf("tunnel: dest %s is revoked — dropping", req.DestNodeID)
		return
	}

	session, err := router.Resolve(req.DestNodeID)
	if err != nil {
		Warnf("tunnel: no route to %s: %v", req.DestNodeID, err)
		return
	}

	stream, err := session.Open()
	if err != nil {
		Infof("tunnel: open stream: %v", err)
		return
	}
	defer func() { _ = stream.Close() }()

	hdr, _ := json.Marshal(streamMsg{
		Type:       "tunnel",
		DestNodeID: req.DestNodeID,
		DestAddr:   req.DestAddr,
	})
	if _, err := stream.Write(append(hdr, '\n')); err != nil {
		Infof("tunnel: write header: %v", err)
		return
	}

	Infof("tunnel: %s → %s@%s", selfID, req.DestNodeID, req.DestAddr)
	bridgeStreamsCounted(reader, client, stream, tc)
}

// HandleRelayStream is called by the dispatcher when a tunnel stream arrives.
// callerNodeID is the verified identity of the peer that opened the stream (from TLS CN).
func HandleRelayStream(stream net.Conn, reader *bufio.Reader, req TunnelRequest, selfID string, callerNodeID string, router *Router, acls *ACLTable, metaLookup MetaLookup, tc *TrafficCounters) {
	defer func() { _ = stream.Close() }()

	if err := validateDestAddr(req.DestAddr); err != nil {
		Warnf("relay: %v", err)
		return
	}

	if req.DestNodeID == selfID || req.DestNodeID == "" {
		// ACL check: is the caller allowed to reach this node/port?
		if callerNodeID != "" && acls != nil {
			port := portFromAddr(req.DestAddr)
			if err := acls.Check(callerNodeID, selfID, port, metaLookup); err != nil {
				Warnf("relay: ACL denied %s → %s: %v", callerNodeID, req.DestAddr, err)
				return
			}
		}
		target, err := dialTarget(req.DestAddr)
		if err != nil {
			Infof("relay: dial %s: %v", req.DestAddr, err)
			return
		}
		defer func() { _ = target.Close() }()
		Infof("relay: terminating → %s", req.DestAddr)
		bridgeCounted(reader, stream, target, tc)
		return
	}

	// ACL check at intermediate relay hop.
	if callerNodeID != "" && acls != nil {
		port := portFromAddr(req.DestAddr)
		if err := acls.Check(callerNodeID, req.DestNodeID, port, metaLookup); err != nil {
			Warnf("relay: ACL denied %s → %s (intermediate hop): %v", callerNodeID, req.DestNodeID, err)
			return
		}
	}

	nextSession, err := router.Resolve(req.DestNodeID)
	if err != nil {
		Warnf("relay: no route to %s: %v", req.DestNodeID, err)
		return
	}
	nextConn, err := nextSession.Open()
	if err != nil {
		Infof("relay: open next stream: %v", err)
		return
	}
	defer func() { _ = nextConn.Close() }()

	hdr, _ := json.Marshal(streamMsg{
		Type:       "tunnel",
		NodeID:     callerNodeID, // propagate caller identity for ACL at terminating hop
		DestNodeID: req.DestNodeID,
		DestAddr:   req.DestAddr,
	})
	if _, err := nextConn.Write(append(hdr, '\n')); err != nil {
		return
	}

	bridgeStreamsCounted(reader, stream, nextConn, tc)
}

// validateDestAddr checks that addr is a valid host:port and not a restricted IP.
func validateDestAddr(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid dest_addr format: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in dest_addr: %s", portStr)
	}
	// Block cloud metadata endpoint (SSRF prevention).
	if ip := net.ParseIP(host); ip != nil && ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return fmt.Errorf("dest_addr targets restricted IP: %s", host)
	}
	return nil
}

// dialTarget dials the final destination and applies TCP_NODELAY immediately.
func dialTarget(addr string) (*net.TCPConn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	setTCPOpts(conn)
	return conn.(*net.TCPConn), nil
}
