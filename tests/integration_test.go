package tests

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/leonardomb1/pulse/cli"
	"github.com/leonardomb1/pulse/config"
	"github.com/leonardomb1/pulse/node"
)

// startTestDaemon starts a pulse daemon in-process for testing.
// Returns the socket path and a cleanup function.
func startTestDaemon(t *testing.T, opts ...func(*config.Config)) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "pulse.sock")

	cfg, _ := config.Load("")
	cfg.Node.DataDir = dir
	cfg.Node.Addr = "127.0.0.1:0" // won't actually accept (port 0)
	cfg.Node.TCPListen = "127.0.0.1:0"
	cfg.CA.Enabled = true
	cfg.CA.DataDir = filepath.Join(dir, "ca")
	cfg.CA.JoinToken = "test-token"
	cfg.Scribe.Enabled = true
	cfg.Scribe.Listen = "127.0.0.1:0"
	cfg.Control.Socket = sock
	cfg.Persist.Enabled = false
	cfg.Node.LogLevel = "error" // quiet

	for _, o := range opts {
		o(cfg)
	}

	node.SetLogLevel(node.LevelError)

	ca, err := cli.LoadOrInitCA(cfg.CA.DataDir, cfg.CA.JoinToken)
	if err != nil {
		t.Fatalf("init CA: %v", err)
	}

	n, err := node.New(cfg, ca)
	if err != nil {
		t.Fatalf("init node: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = n.Run(ctx)
		close(done)
	}()

	// Wait for control socket.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(sock); err != nil {
		cancel()
		t.Fatalf("socket not created: %v", err)
	}

	cleanup := func() {
		cancel()
		<-done
	}
	return sock, cleanup
}

func TestIntegrationStatus(t *testing.T) {
	sock, cleanup := startTestDaemon(t)
	defer cleanup()

	resp, err := cli.CtrlDo(sock, map[string]string{"cmd": "status"})
	if err != nil {
		t.Fatalf("status: %v", err)
	}

	var selfID string
	_ = json.Unmarshal(resp["self"], &selfID)
	if selfID == "" {
		t.Fatal("empty self ID")
	}

	var networkID string
	_ = json.Unmarshal(resp["network_id"], &networkID)
	// Should be empty (not set in test)

	var peers []node.PeerEntry
	_ = json.Unmarshal(resp["peers"], &peers)
	// Should have at least self
	if len(peers) == 0 {
		t.Fatal("no peers in status")
	}

	// Self should have mesh IP populated
	for _, p := range peers {
		if p.NodeID == selfID && p.MeshIP == "" {
			t.Error("self peer should have mesh IP")
		}
	}
}

func TestIntegrationNetworkID(t *testing.T) {
	sock, cleanup := startTestDaemon(t, func(cfg *config.Config) {
		cfg.Node.NetworkID = "test-net"
	})
	defer cleanup()

	resp, err := cli.CtrlDo(sock, map[string]string{"cmd": "status"})
	if err != nil {
		t.Fatalf("status: %v", err)
	}

	var networkID string
	_ = json.Unmarshal(resp["network_id"], &networkID)
	if networkID != "test-net" {
		t.Errorf("network_id = %q, want test-net", networkID)
	}
}

func TestIntegrationToken(t *testing.T) {
	sock, cleanup := startTestDaemon(t)
	defer cleanup()

	// Legacy master token.
	resp, err := cli.CtrlDo(sock, map[string]string{"cmd": "token"})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var token string
	_ = json.Unmarshal(resp["token"], &token)
	if token != "test-token" {
		t.Errorf("token = %q, want test-token", token)
	}
}

func TestIntegrationTokenCRUD(t *testing.T) {
	sock, cleanup := startTestDaemon(t)
	defer cleanup()

	// Create.
	resp, err := cli.CtrlDo(sock, map[string]interface{}{
		"cmd": "token-create", "ttl": "1h", "max_uses": 5,
	})
	if err != nil {
		t.Fatalf("token-create: %v", err)
	}
	var created node.JoinToken
	_ = json.Unmarshal(resp["token"], &created)
	if len(created.Value) != 64 {
		t.Fatalf("token value length = %d", len(created.Value))
	}
	if created.MaxUses != 5 {
		t.Errorf("max_uses = %d", created.MaxUses)
	}

	// List.
	resp, _ = cli.CtrlDo(sock, map[string]string{"cmd": "token-list"})
	var tokens []node.JoinToken
	_ = json.Unmarshal(resp["tokens"], &tokens)
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}

	// Revoke.
	_, err = cli.CtrlDo(sock, map[string]interface{}{
		"cmd": "token-revoke", "token_prefix": created.Value[:8],
	})
	if err != nil {
		t.Fatalf("token-revoke: %v", err)
	}

	resp, _ = cli.CtrlDo(sock, map[string]string{"cmd": "token-list"})
	_ = json.Unmarshal(resp["tokens"], &tokens)
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens after revoke, got %d", len(tokens))
	}
}

func TestIntegrationDNSCRUD(t *testing.T) {
	sock, cleanup := startTestDaemon(t)
	defer cleanup()

	// Add.
	_, err := cli.CtrlDo(sock, map[string]interface{}{
		"cmd":  "dns-add",
		"zone": map[string]interface{}{"name": "test.pulse", "type": "A", "value": "10.0.0.1", "ttl": 60},
	})
	if err != nil {
		t.Fatalf("dns-add: %v", err)
	}

	// List.
	resp, _ := cli.CtrlDo(sock, map[string]string{"cmd": "dns-list"})
	var zones []node.DNSZone
	_ = json.Unmarshal(resp["zones"], &zones)
	if len(zones) != 1 || zones[0].Name != "test.pulse" {
		t.Fatalf("dns-list: %+v", zones)
	}

	// Remove.
	_, _ = cli.CtrlDo(sock, map[string]string{"cmd": "dns-remove", "name": "test.pulse", "type": "A"})
	resp, _ = cli.CtrlDo(sock, map[string]string{"cmd": "dns-list"})
	_ = json.Unmarshal(resp["zones"], &zones)
	if len(zones) != 0 {
		t.Errorf("expected 0 zones, got %d", len(zones))
	}
}

func TestIntegrationRouteCRUD(t *testing.T) {
	sock, cleanup := startTestDaemon(t)
	defer cleanup()

	// Add.
	_, err := cli.CtrlDo(sock, map[string]string{
		"cmd": "route-add", "cidr": "10.0.0.0/8", "via": "fake-node-id",
	})
	if err != nil {
		t.Fatalf("route-add: %v", err)
	}

	// List.
	resp, _ := cli.CtrlDo(sock, map[string]string{"cmd": "route-list"})
	var routes []json.RawMessage
	_ = json.Unmarshal(resp["routes"], &routes)
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}

	// Remove.
	_, _ = cli.CtrlDo(sock, map[string]string{"cmd": "route-remove", "cidr": "10.0.0.0/8"})
	resp, _ = cli.CtrlDo(sock, map[string]string{"cmd": "route-list"})
	_ = json.Unmarshal(resp["routes"], &routes)
	if len(routes) != 0 {
		t.Errorf("expected 0 routes, got %d", len(routes))
	}
}

func TestIntegrationACLCRUD(t *testing.T) {
	sock, cleanup := startTestDaemon(t)
	defer cleanup()

	// Add.
	rule := node.ACLRule{Action: "deny", SrcPattern: "tag:dev", DstPattern: "tag:prod"}
	_, err := cli.CtrlDo(sock, map[string]interface{}{"cmd": "acl-add", "acl_rule": rule})
	if err != nil {
		t.Fatalf("acl-add: %v", err)
	}

	// List.
	resp, _ := cli.CtrlDo(sock, map[string]string{"cmd": "acl-list"})
	var rules []node.ACLRule
	_ = json.Unmarshal(resp["rules"], &rules)
	if len(rules) != 1 || rules[0].Action != "deny" {
		t.Fatalf("acl-list: %+v", rules)
	}

	// Remove.
	_, _ = cli.CtrlDo(sock, map[string]interface{}{"cmd": "acl-remove", "index": 0})
	resp, _ = cli.CtrlDo(sock, map[string]string{"cmd": "acl-list"})
	_ = json.Unmarshal(resp["rules"], &rules)
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestIntegrationTagAndName(t *testing.T) {
	sock, cleanup := startTestDaemon(t)
	defer cleanup()

	// Get self ID.
	resp, _ := cli.CtrlDo(sock, map[string]string{"cmd": "status"})
	var selfID string
	_ = json.Unmarshal(resp["self"], &selfID)

	// Tag.
	_, err := cli.CtrlDo(sock, map[string]string{"cmd": "tag-add", "node_id": selfID, "tag": "prod"})
	if err != nil {
		t.Fatalf("tag-add: %v", err)
	}

	// Name.
	_, err = cli.CtrlDo(sock, map[string]string{"cmd": "name-set", "node_id": selfID, "name": "test-node"})
	if err != nil {
		t.Fatalf("name-set: %v", err)
	}

	// Wait for netconfig broadcast to propagate metadata overlay.
	time.Sleep(2 * time.Second)

	// Verify in status.
	resp, _ = cli.CtrlDo(sock, map[string]string{"cmd": "status"})
	var peers []node.PeerEntry
	_ = json.Unmarshal(resp["peers"], &peers)

	found := false
	for _, p := range peers {
		if p.NodeID == selfID {
			if p.Name != "test-node" {
				t.Errorf("name = %q, want test-node", p.Name)
			}
			if len(p.Tags) != 1 || p.Tags[0] != "prod" {
				t.Errorf("tags = %v, want [prod]", p.Tags)
			}
			found = true
		}
	}
	if !found {
		t.Error("self not found in peers")
	}

	// Untag — verify the command succeeds (propagation tested via live mesh).
	_, err = cli.CtrlDo(sock, map[string]string{"cmd": "tag-remove", "node_id": selfID, "tag": "prod"})
	if err != nil {
		t.Fatalf("tag-remove: %v", err)
	}
}

func TestIntegrationRevoke(t *testing.T) {
	sock, cleanup := startTestDaemon(t)
	defer cleanup()

	// Revoke a fake node (scribe should accept it).
	_, err := cli.CtrlDo(sock, map[string]string{"cmd": "revoke", "node_id": "deadbeef12345678"})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

func TestIntegrationStop(t *testing.T) {
	sock, cleanup := startTestDaemon(t)
	_ = cleanup

	resp, err := cli.CtrlDo(sock, map[string]string{"cmd": "stop"})
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	// stop command should return OK.
	if resp == nil {
		t.Fatal("stop returned nil response")
	}
}

func TestIntegrationNonScribeRejects(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "pulse.sock")

	cfg, _ := config.Load("")
	cfg.Node.DataDir = dir
	cfg.Node.Addr = "127.0.0.1:0"
	cfg.Node.TCPListen = "127.0.0.1:0"
	cfg.Scribe.Enabled = false // NOT a scribe
	cfg.CA.Enabled = false
	cfg.Control.Socket = sock
	cfg.Persist.Enabled = false
	cfg.Node.LogLevel = "error"

	node.SetLogLevel(node.LevelError)

	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGUSR2) // won't fire
	defer cancel()
	done := make(chan struct{})
	go func() { _ = n.Run(ctx); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Scribe-only commands should fail.
	for _, cmd := range []string{"tag-add", "tag-remove", "name-set", "acl-add", "acl-remove", "token-create", "token-list", "token-revoke"} {
		_, err := cli.CtrlDo(sock, map[string]string{"cmd": cmd, "node_id": "x", "tag": "x"})
		if err == nil {
			t.Errorf("cmd %q should fail on non-scribe node", cmd)
		}
	}

	// Token should fail (not CA).
	_, err = cli.CtrlDo(sock, map[string]string{"cmd": "token"})
	if err == nil {
		t.Error("token should fail on non-CA node")
	}

	cancel()
	<-done
}
