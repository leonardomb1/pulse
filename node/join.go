package node

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
)

func (n *Node) handleJoinConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	var msg streamMsg
	if err := json.Unmarshal([]byte(line), &msg); err != nil || msg.Type != "join" || msg.JoinReq == nil {
		return
	}
	resp := n.resolveJoin(*msg.JoinReq)
	reply, _ := json.Marshal(streamMsg{Type: "join_response", JoinResp: &resp})
	_, _ = conn.Write(append(reply, '\n'))
}

func (n *Node) resolveJoin(req JoinRequest) JoinResponse {
	if n.ca != nil {
		return n.ca.HandleJoin(req)
	}
	caEntry, ok := n.table.FindCA()
	if !ok {
		return JoinResponse{Error: "CA node not reachable from this relay"}
	}
	session, err := n.router.Resolve(caEntry.NodeID)
	if err != nil {
		return JoinResponse{Error: fmt.Sprintf("no route to CA: %v", err)}
	}
	conn, err := session.Open()
	if err != nil {
		return JoinResponse{Error: fmt.Sprintf("open stream to CA: %v", err)}
	}
	defer conn.Close()

	fwd, _ := json.Marshal(streamMsg{Type: "join", JoinReq: &req})
	_, _ = conn.Write(append(fwd, '\n'))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return JoinResponse{Error: "no response from CA"}
	}
	var reply streamMsg
	if err := json.Unmarshal([]byte(line), &reply); err != nil || reply.JoinResp == nil {
		return JoinResponse{Error: "malformed CA response"}
	}
	return *reply.JoinResp
}

// Join connects to a relay's /join endpoint for first-time bootstrapping.
func Join(ctx context.Context, relayAddr string, req JoinRequest) (*JoinResponse, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	session, err := dialPeer(ctx, relayAddr, tlsCfg, "/join")
	if err != nil {
		return nil, fmt.Errorf("connect to relay: %w", err)
	}
	defer session.Close()

	conn, err := session.Open()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	msg, _ := json.Marshal(streamMsg{Type: "join", JoinReq: &req})
	_, _ = conn.Write(append(msg, '\n'))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	var reply streamMsg
	if err := json.Unmarshal([]byte(line), &reply); err != nil || reply.JoinResp == nil {
		return nil, errors.New("malformed join response")
	}
	if reply.JoinResp.Error != "" {
		return nil, errors.New(reply.JoinResp.Error)
	}
	return reply.JoinResp, nil
}

// resolveDNSBootstrap queries _pulse.<domain> TXT records for relay addresses.
// Records must be formatted as: relay=host:port
func resolveDNSBootstrap(ctx context.Context, domain string) ([]string, error) {
	records, err := net.DefaultResolver.LookupTXT(ctx, "_pulse."+domain)
	if err != nil {
		return nil, err
	}
	var addrs []string
	for _, rec := range records {
		for _, field := range strings.Fields(rec) {
			if after, ok := strings.CutPrefix(field, "relay="); ok {
				addrs = append(addrs, after)
			}
		}
	}
	return addrs, nil
}
