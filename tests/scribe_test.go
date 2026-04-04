package tests

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"github.com/leonardomb1/pulse/cli"
	"github.com/leonardomb1/pulse/config"
	"github.com/leonardomb1/pulse/node"
	"testing"
	"time"
)

func TestScribePersistence(t *testing.T) {
	sock, cleanup := startTestDaemon(t)
	defer cleanup()

	// Add DNS zone.
	cli.CtrlDo(sock, map[string]interface{}{
		"cmd":  "dns-add",
		"zone": map[string]interface{}{"name": "test.pulse", "type": "A", "value": "10.0.0.1", "ttl": 60},
	})

	// Add ACL rule.
	cli.CtrlDo(sock, map[string]interface{}{
		"cmd":      "acl-add",
		"acl_rule": map[string]interface{}{"action": "deny", "src_pat": "tag:x", "dst_pat": "*"},
	})

	// Create token.
	cli.CtrlDo(sock, map[string]interface{}{
		"cmd": "token-create", "ttl": "1h", "max_uses": 1,
	})

	// Get self ID and tag it.
	resp, _ := cli.CtrlDo(sock, map[string]string{"cmd": "status"})
	var selfID string
	json.Unmarshal(resp["self"], &selfID)
	cli.CtrlDo(sock, map[string]string{"cmd": "tag-add", "node_id": selfID, "tag": "test"})
	cli.CtrlDo(sock, map[string]string{"cmd": "name-set", "node_id": selfID, "name": "mynode"})

	time.Sleep(1 * time.Second)

	// Stop and check that netconfig.json was written.
	cleanup()

	// Find the data dir from the socket path.
	dataDir := filepath.Dir(sock)
	ncPath := filepath.Join(dataDir, "netconfig.json")
	data, err := os.ReadFile(ncPath)
	if err != nil {
		t.Fatalf("read netconfig.json: %v", err)
	}

	var state struct {
		RevokedIDs []string                   `json:"revoked_ids"`
		DNSZones   []node.DNSZone             `json:"dns_zones"`
		GlobalACLs []node.NodeACL             `json:"global_acls"`
		NodeMeta   map[string]node.NodeMeta   `json:"node_meta"`
		Tokens     []node.JoinToken           `json:"tokens"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(state.DNSZones) != 1 || state.DNSZones[0].Name != "test.pulse" {
		t.Errorf("DNS zones: %+v", state.DNSZones)
	}
	if len(state.GlobalACLs) != 1 || len(state.GlobalACLs[0].Allow) != 1 {
		t.Errorf("ACLs: %+v", state.GlobalACLs)
	}
	if len(state.Tokens) != 1 {
		t.Errorf("tokens: %+v", state.Tokens)
	}
	if meta, ok := state.NodeMeta[selfID]; !ok || meta.Name != "mynode" {
		t.Errorf("node meta: %+v", state.NodeMeta)
	}
}

func TestScribeNonScribeRejectsAllMutations(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "pulse.sock")

	cfg, _ := config.Load("")
	cfg.Node.DataDir = dir
	cfg.Node.Addr = "127.0.0.1:0"
	cfg.Node.TCPListen = "127.0.0.1:0"
	cfg.CA.Enabled = false
	cfg.Scribe.Enabled = false
	cfg.Control.Socket = sock
	cfg.Persist.Enabled = false
	cfg.Node.LogLevel = "error"
	node.SetLogLevel(node.LevelError)

	n, _ := node.New(cfg, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	mutationCmds := []map[string]interface{}{
		{"cmd": "dns-add", "zone": map[string]interface{}{"name": "x", "type": "A", "value": "1"}},
		{"cmd": "dns-remove", "name": "x"},
		{"cmd": "acl-add", "acl_rule": map[string]interface{}{"action": "allow", "dst_pat": "*"}},
		{"cmd": "acl-remove", "index": 0},
		{"cmd": "tag-add", "node_id": "x", "tag": "y"},
		{"cmd": "tag-remove", "node_id": "x", "tag": "y"},
		{"cmd": "name-set", "node_id": "x", "name": "y"},
		{"cmd": "revoke", "node_id": "x"},
		{"cmd": "token-create", "ttl": "1h"},
		{"cmd": "token-list"},
		{"cmd": "token-revoke", "token_prefix": "x"},
	}

	for _, cmd := range mutationCmds {
		_, err := cli.CtrlDo(sock, cmd)
		if err == nil {
			t.Errorf("cmd %v should fail on non-scribe", cmd["cmd"])
		}
	}
}
