package tests

import (
	"github.com/leonardomb1/pulse/config"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDefaults(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}

	if cfg.Node.Addr != ":8443" {
		t.Errorf("Node.Addr = %q, want :8443", cfg.Node.Addr)
	}
	if cfg.Node.TCPListen != ":7000" {
		t.Errorf("Node.TCPListen = %q, want :7000", cfg.Node.TCPListen)
	}
	if cfg.SOCKS.Listen != ":1080" {
		t.Errorf("SOCKS.Listen = %q, want :1080", cfg.SOCKS.Listen)
	}
	if cfg.DNS.Listen != "127.0.0.1:5353" {
		t.Errorf("DNS.Listen = %q, want 127.0.0.1:5353", cfg.DNS.Listen)
	}
	if cfg.Scribe.Listen != "127.0.0.1:8080" {
		t.Errorf("Scribe.Listen = %q, want 127.0.0.1:8080", cfg.Scribe.Listen)
	}
	if cfg.Tun.Name != "pulse0" {
		t.Errorf("Tun.Name = %q, want pulse0", cfg.Tun.Name)
	}
	if cfg.Tun.CIDR != "10.100.0.0/16" {
		t.Errorf("Tun.CIDR = %q, want 10.100.0.0/16", cfg.Tun.CIDR)
	}
	if !cfg.Persist.Enabled {
		t.Error("Persist.Enabled should default to true")
	}
	if cfg.Persist.Interval != 60 {
		t.Errorf("Persist.Interval = %d, want 60", cfg.Persist.Interval)
	}

	// Features should default to off.
	if cfg.CA.Enabled {
		t.Error("CA should default to disabled")
	}
	if cfg.SOCKS.Enabled {
		t.Error("SOCKS should default to disabled")
	}
	if cfg.DNS.Enabled {
		t.Error("DNS should default to disabled")
	}
	if cfg.Tun.Enabled {
		t.Error("TUN should default to disabled")
	}
	if cfg.Scribe.Enabled {
		t.Error("Scribe should default to disabled")
	}
	if cfg.Exit.Enabled {
		t.Error("Exit should default to disabled")
	}
}

func TestConfigFromTOML(t *testing.T) {
	toml := `
[node]
addr       = "relay.example.com:443"
listen     = ":443"
tcp_listen = ":9000"
data_dir   = "/opt/pulse/data"
network_id = "production"
log_level  = "debug"

[ca]
enabled    = true
data_dir   = "/opt/pulse/ca"
join_token = "secret123"

[scribe]
enabled = true
listen  = "0.0.0.0:9090"

[bootstrap]
peers = ["peer1:443", "peer2:443"]

[join]
relay_addr = "relay:443"
token      = "join-token"

[socks]
enabled = true
listen  = "127.0.0.1:1081"

[dns]
enabled = true
listen  = "127.0.0.1:5454"

[exit]
enabled = true
cidrs   = ["0.0.0.0/0", "10.0.0.0/8"]

[tun]
enabled = true
name    = "mesh0"
cidr    = "10.200.0.0/16"

[persist]
enabled  = false
interval = 30

[control]
socket = "/tmp/test.sock"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	_ = os.WriteFile(path, []byte(toml), 0644)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Node
	if cfg.Node.Addr != "relay.example.com:443" {
		t.Errorf("Node.Addr = %q", cfg.Node.Addr)
	}
	if cfg.Node.Listen != ":443" {
		t.Errorf("Node.Listen = %q", cfg.Node.Listen)
	}
	if cfg.Node.TCPListen != ":9000" {
		t.Errorf("Node.TCPListen = %q", cfg.Node.TCPListen)
	}
	if cfg.Node.DataDir != "/opt/pulse/data" {
		t.Errorf("Node.DataDir = %q", cfg.Node.DataDir)
	}
	if cfg.Node.NetworkID != "production" {
		t.Errorf("Node.NetworkID = %q", cfg.Node.NetworkID)
	}
	if cfg.Node.LogLevel != "debug" {
		t.Errorf("Node.LogLevel = %q", cfg.Node.LogLevel)
	}

	// CA
	if !cfg.CA.Enabled {
		t.Error("CA should be enabled")
	}
	if cfg.CA.DataDir != "/opt/pulse/ca" {
		t.Errorf("CA.DataDir = %q", cfg.CA.DataDir)
	}
	if cfg.CA.JoinToken != "secret123" {
		t.Errorf("CA.JoinToken = %q", cfg.CA.JoinToken)
	}

	// Scribe
	if !cfg.Scribe.Enabled || cfg.Scribe.Listen != "0.0.0.0:9090" {
		t.Errorf("Scribe: enabled=%v listen=%q", cfg.Scribe.Enabled, cfg.Scribe.Listen)
	}

	// Bootstrap
	if len(cfg.Bootstrap.Peers) != 2 {
		t.Errorf("Bootstrap.Peers = %v", cfg.Bootstrap.Peers)
	}

	// Join
	if cfg.Join.RelayAddr != "relay:443" || cfg.Join.Token != "join-token" {
		t.Errorf("Join: relay=%q token=%q", cfg.Join.RelayAddr, cfg.Join.Token)
	}

	// SOCKS
	if !cfg.SOCKS.Enabled || cfg.SOCKS.Listen != "127.0.0.1:1081" {
		t.Errorf("SOCKS: enabled=%v listen=%q", cfg.SOCKS.Enabled, cfg.SOCKS.Listen)
	}

	// DNS
	if !cfg.DNS.Enabled || cfg.DNS.Listen != "127.0.0.1:5454" {
		t.Errorf("DNS: enabled=%v listen=%q", cfg.DNS.Enabled, cfg.DNS.Listen)
	}

	// Exit
	if !cfg.Exit.Enabled || len(cfg.Exit.CIDRs) != 2 {
		t.Errorf("Exit: enabled=%v cidrs=%v", cfg.Exit.Enabled, cfg.Exit.CIDRs)
	}

	// TUN
	if !cfg.Tun.Enabled || cfg.Tun.Name != "mesh0" || cfg.Tun.CIDR != "10.200.0.0/16" {
		t.Errorf("Tun: enabled=%v name=%q cidr=%q", cfg.Tun.Enabled, cfg.Tun.Name, cfg.Tun.CIDR)
	}

	// Persist
	if cfg.Persist.Enabled || cfg.Persist.Interval != 30 {
		t.Errorf("Persist: enabled=%v interval=%d", cfg.Persist.Enabled, cfg.Persist.Interval)
	}

	// Control
	if cfg.Control.Socket != "/tmp/test.sock" {
		t.Errorf("Control.Socket = %q", cfg.Control.Socket)
	}
}

func TestConfigPartialOverride(t *testing.T) {
	// Only override a few fields — rest should keep defaults.
	toml := `
[node]
addr = "myhost:8443"

[ca]
enabled = true
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	_ = os.WriteFile(path, []byte(toml), 0644)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Node.Addr != "myhost:8443" {
		t.Errorf("overridden Addr = %q", cfg.Node.Addr)
	}
	if cfg.Node.TCPListen != ":7000" {
		t.Errorf("default TCPListen should be :7000, got %q", cfg.Node.TCPListen)
	}
	if !cfg.CA.Enabled {
		t.Error("CA should be enabled")
	}
	if cfg.SOCKS.Enabled {
		t.Error("SOCKS should still be disabled")
	}
}

func TestConfigMissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Fatal("should error on missing file")
	}
}

func TestConfigDNSServices(t *testing.T) {
	toml := `
[dns]
enabled = true

[[dns.service]]
name     = "postgres"
port     = 5432
priority = 10

[[dns.service]]
name = "redis"
port = 6379
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	_ = os.WriteFile(path, []byte(toml), 0644)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.DNS.Services) != 2 {
		t.Fatalf("expected 2 DNS services, got %d", len(cfg.DNS.Services))
	}
	if cfg.DNS.Services[0].Name != "postgres" || cfg.DNS.Services[0].Port != 5432 {
		t.Errorf("service 0: %+v", cfg.DNS.Services[0])
	}
	if cfg.DNS.Services[1].Name != "redis" || cfg.DNS.Services[1].Port != 6379 {
		t.Errorf("service 1: %+v", cfg.DNS.Services[1])
	}
}
