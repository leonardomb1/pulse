package node

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"time"
)

// authedConn wraps a net.Conn with the caller's verified nodeID (from TLS CN).
type authedConn struct {
	net.Conn
	callerNodeID string
	session      Session
}

func (n *Node) onPeerSession(ctx context.Context, session Session, hint, callerID string) {
	go n.sendHandshake(session)
	for {
		conn, err := session.Accept()
		if err != nil {
			break
		}
		go n.dispatchStream(&authedConn{Conn: conn, callerNodeID: callerID, session: session})
	}
}

func (n *Node) sendHandshake(session Session) {
	conn, err := session.Open()
	if err != nil {
		return
	}
	defer conn.Close()

	// Include mesh IP if tun is active.
	meshIP := ""
	if n.cfg.Tun.Enabled {
		meshIP = MeshIPFromNodeID(n.id).String()
	}

	scribeAPIAddr := ""
	if n.cfg.Scribe.Enabled {
		scribeAPIAddr = n.cfg.Scribe.Listen
	}
	msg := streamMsg{
		Type:          "handshake",
		NodeID:        n.id,
		NetworkID:     n.cfg.Node.NetworkID,
		Addr:          n.cfg.Node.Addr,
		PublicKey:     n.identity.PublicKey,
		IsCA:          n.ca != nil,
		IsExit:        n.cfg.Exit.Enabled,
		IsScribe:      n.cfg.Scribe.Enabled,
		ScribeAPIAddr: scribeAPIAddr,
		MeshIP:        meshIP,
	}
	line, _ := json.Marshal(msg)
	_, _ = conn.Write(append(line, '\n'))
}

func (n *Node) dispatchStream(ac *authedConn) {
	reader := bufio.NewReader(ac)
	line, err := reader.ReadString('\n')
	if err != nil {
		ac.Close()
		return
	}
	var msg streamMsg
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		ac.Close()
		return
	}

	// Revocation check: reject any stream (except handshake itself) from a revoked node.
	if msg.Type != "handshake" && ac.callerNodeID != "" && n.netCfg.isRevoked(ac.callerNodeID) {
		Warnf("revocation: rejected stream type=%q from %s", msg.Type, ac.callerNodeID)
		ac.Close()
		return
	}

	switch msg.Type {
	case "handshake":
		n.handleHandshake(msg, ac)
		ac.Close()

	case "gossip":
		n.table.MergeFrom(msg.Entries, n.id)
		// ACLs from gossip are unsigned — only scribe-signed NetworkConfig ACLs are trusted.
		Debugf("gossip: merged %d entries", len(msg.Entries))
		ac.Close()

	case "probe":
		pong, _ := json.Marshal(streamMsg{Type: "pong", SentAt: msg.SentAt})
		_, _ = ac.Write(append(pong, '\n'))
		ac.Close()

	case "join":
		if msg.JoinReq == nil {
			ac.Close()
			return
		}
		resp := n.resolveJoin(*msg.JoinReq)
		reply, _ := json.Marshal(streamMsg{Type: "join_response", JoinResp: &resp})
		_, _ = ac.Write(append(reply, '\n'))
		ac.Close()

	case "punch_start":
		// Reply on the same stream, then probe. Don't close ac here —
		// HandlePunchStart writes the ack on it before probing.
		go func() {
			defer ac.Close()
			n.nat.HandlePunchStart(context.Background(),
				ac, msg.PunchNodeID, msg.PunchAddr, msg.PunchToken)
		}()

	case "netconfig":
		if msg.NetConfig != nil {
			n.mergeNetConfig(*msg.NetConfig)
		}
		ac.Close()

	case "stats":
		if msg.Stats != nil && n.scribe != nil {
			n.scribe.AcceptStats(*msg.Stats)
		}
		ac.Close()

	case "revoke":
		// A node forwarding a revoke request to the scribe.
		if msg.RevokeNodeID != "" && n.scribe != nil {
			go n.scribe.Revoke(msg.RevokeNodeID)
		}
		ac.Close()

	case "tunpipe":
		// Persistent bidirectional packet pipe — one per peer pair.
		// The remote side initiated; run the pipe read loop (blocks until closed).
		if n.tun != nil {
			n.tun.RunPipe(msg.NodeID, ac.Conn)
		} else {
			ac.Close()
		}

	case "tun":
		// Legacy one-shot stream, used before a pipe is established.
		if n.tun != nil {
			n.tun.HandleInbound(ac.Conn)
		} else {
			ac.Close()
		}

	case "tunnel":
		req := TunnelRequest{DestNodeID: msg.DestNodeID, DestAddr: msg.DestAddr}
		callerID := ac.callerNodeID
		if callerID == "" {
			callerID = msg.NodeID // fallback: use handshake-announced ID
		}
		if n.netCfg.isRevoked(req.DestNodeID) {
			Warnf("tunnel: dest %s is revoked — dropping", req.DestNodeID)
			ac.Close()
			return
		}
		HandleRelayStream(ac.Conn, reader, req, n.id, callerID, n.router, n.aclTable, n.netCfg.nodeMeta, &n.traffic)

	default:
		Infof("unknown stream type: %q", msg.Type)
		ac.Close()
	}
}

// mergeNetConfig accepts a SignedNetConfig from the scribe, verifies it, and
// if the version is newer, applies it and propagates to all peers.
func (n *Node) mergeNetConfig(snc SignedNetConfig) {
	// Look up scribe public key from gossip table.
	scribeEntry, ok := n.table.Get(snc.ScribeID)
	if !ok {
		Infof("netconfig: scribe %s not in table — ignoring", snc.ScribeID)
		return
	}
	if len(scribeEntry.PublicKey) == 0 {
		Infof("netconfig: scribe %s has no public key in gossip table — ignoring", snc.ScribeID)
		return
	}
	if err := VerifyNetConfig(snc, scribeEntry.PublicKey); err != nil {
		Warnf("netconfig: verification failed: %v", err)
		return
	}
	if !n.netCfg.merge(snc) {
		return // not newer
	}
	Warnf("netconfig: v%d applied (%d revoked, %d dns zones, %d node meta)",
		snc.Config.Version, len(snc.Config.RevokedIDs), len(snc.Config.DNSZones), len(snc.Config.NodeMeta))

	// Overlay node metadata onto gossip table entries.
	for nodeID, meta := range snc.Config.NodeMeta {
		if entry, ok := n.table.Get(nodeID); ok {
			entry.Name = meta.Name
			entry.Tags = meta.Tags
			n.table.UpsertForce(entry)
		}
	}

	// Sync ACL table from scribe-signed config (only trusted source).
	for _, acl := range snc.Config.GlobalACLs {
		n.aclTable.Upsert(acl)
	}

	// Keep CA in sync with scribe state.
	if n.ca != nil {
		n.ca.SyncRevokedIDs(snc.Config.RevokedIDs)
		n.ca.SyncTokens(snc.Config.JoinTokens)
	}

	// Propagate to all peers (flood — scribe is authoritative, Version prevents loops).
	for _, link := range n.registry.All() {
		if link.IsClosed() {
			continue
		}
		conn, err := link.Open()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			msg, _ := marshalStreamMsg(streamMsg{Type: "netconfig", NetConfig: &snc})
			_, _ = c.Write(msg)
		}(conn)
	}
}

func (n *Node) handleHandshake(msg streamMsg, ac *authedConn) {
	if msg.NodeID == "" {
		return
	}
	callerID := ac.callerNodeID
	nodeID := callerID
	if nodeID == "" {
		nodeID = msg.NodeID
	}

	// Verify that the announced nodeID matches the public key.
	if len(msg.PublicKey) > 0 {
		expectedID := nodeIDFromKey(msg.PublicKey)
		if msg.NodeID != expectedID {
			Warnf("handshake: nodeID %s does not match public key (expected %s) — rejecting", msg.NodeID, expectedID)
			return
		}
	}

	// Reject connections from revoked nodes immediately.
	if n.netCfg.isRevoked(nodeID) {
		Warnf("handshake: rejecting revoked node %s", nodeID)
		return
	}

	// Network ID isolation: reject peers from different networks.
	myNet := n.cfg.Node.NetworkID
	peerNet := msg.NetworkID
	if myNet != "" && peerNet != "" && myNet != peerNet {
		Infof("handshake: rejecting node %s from network %q (we are %q)", nodeID, peerNet, myNet)
		return
	}

	Infof("handshake: node=%s addr=%s isCA=%v isExit=%v isScribe=%v meshIP=%s",
		nodeID, msg.Addr, msg.IsCA, msg.IsExit, msg.IsScribe, msg.MeshIP)
	n.table.Upsert(PeerEntry{
		NodeID:        nodeID,
		Addr:          msg.Addr,
		PublicKey:     msg.PublicKey,
		IsCA:          msg.IsCA,
		IsExit:        msg.IsExit,
		IsScribe:      msg.IsScribe,
		ScribeAPIAddr: msg.ScribeAPIAddr,
		MeshIP:        msg.MeshIP,
		LastSeen:      time.Now(),
		HopCount:      0,
	})

	// Register the session in the link registry so the router can use it.
	// This is the moment we first learn the peer's nodeID, so we register here.
	if ac.session != nil {
		n.registry.Add(newPeerLink(nodeID, ac.session))
		Infof("handshake: registered link to %s", nodeID)
	}

	// If we're the scribe, immediately push the current NetworkConfig to the
	// new peer so it doesn't have to wait up to 60s for the next broadcast.
	// This also covers nodes coming back online after a restart.
	if n.scribe != nil && ac.session != nil {
		go n.scribe.PushTo(ac.session)
	}

	// If TUN is active, immediately rebuild the mesh IP→nodeID map so that
	// reply packets from this newly-joined peer route correctly without waiting
	// for the background 5-second refresh tick.
	if n.tun != nil {
		n.tun.RefreshMeshIPs()
		// Initiate a persistent bidirectional pipe if the peer also has TUN.
		// Lower nodeID initiates to avoid both sides racing to open a pipe.
		if msg.MeshIP != "" && n.id < nodeID && ac.session != nil {
			go n.openTunPipe(nodeID, ac.session)
		}
	}
}

// openTunPipe opens a persistent bidirectional yamux stream to the peer for
// all TUN traffic. One stream handles both directions — no per-packet overhead.
func (n *Node) openTunPipe(nodeID string, session Session) {
	conn, err := session.Open()
	if err != nil {
		tunLog("open pipe to %s: %v", nodeID, err)
		return
	}
	hdr, _ := marshalStreamMsg(streamMsg{Type: "tunpipe", NodeID: n.id})
	if _, err := conn.Write(hdr); err != nil {
		conn.Close()
		return
	}
	n.tun.RunPipe(nodeID, conn)
}
