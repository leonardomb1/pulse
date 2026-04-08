package tests

import (
	"github.com/leonardomb1/pulse/cli"
	"github.com/leonardomb1/pulse/config"
	"testing"
)

func TestApplyFlagsDataDir(t *testing.T) {
	cfg := config.Defaults()

	cli.ApplyFlags(cfg,
		"", "", "", "/tmp/test-pulse", "", "", "",
		false, "",
		false, "",
		false, "",
		false, 0, false,
		false, "",
		false, "", "",
	)

	if cfg.Node.DataDir != "/tmp/test-pulse" {
		t.Errorf("DataDir = %q, want /tmp/test-pulse", cfg.Node.DataDir)
	}
	if cfg.CA.DataDir != "/tmp/test-pulse/ca" {
		t.Errorf("CA.DataDir = %q", cfg.CA.DataDir)
	}
	if cfg.Control.Socket != "/tmp/test-pulse/pulse.sock" {
		t.Errorf("Control.Socket = %q", cfg.Control.Socket)
	}
	if cfg.Exit.RoutesFile != "/tmp/test-pulse/routes.json" {
		t.Errorf("Exit.RoutesFile = %q", cfg.Exit.RoutesFile)
	}
}

func TestApplyFlagsFeatures(t *testing.T) {
	cfg := config.Defaults()

	cli.ApplyFlags(cfg,
		"relay:443", ":443", ":9000", "", "prod", "", "mytoken",
		true, "ca-secret",
		true, "127.0.0.1:1081",
		true, "127.0.0.1:5454",
		true, 4, false,
		true, "0.0.0.0:9090",
		true, "10.0.0.0/8,192.168.0.0/16", "172.16.0.0/12",
	)

	if cfg.Node.Addr != "relay:443" {
		t.Errorf("Addr = %q", cfg.Node.Addr)
	}
	if cfg.Node.Listen != ":443" {
		t.Errorf("Listen = %q", cfg.Node.Listen)
	}
	if cfg.Node.TCPListen != ":9000" {
		t.Errorf("TCPListen = %q", cfg.Node.TCPListen)
	}
	if cfg.Node.NetworkID != "prod" {
		t.Errorf("NetworkID = %q", cfg.Node.NetworkID)
	}
	if !cfg.CA.Enabled {
		t.Error("CA should be enabled")
	}
	if cfg.CA.JoinToken != "ca-secret" {
		t.Errorf("CA.JoinToken = %q, want ca-secret", cfg.CA.JoinToken)
	}
	if !cfg.SOCKS.Enabled || cfg.SOCKS.Listen != "127.0.0.1:1081" {
		t.Errorf("SOCKS: %v %q", cfg.SOCKS.Enabled, cfg.SOCKS.Listen)
	}
	if !cfg.DNS.Enabled || cfg.DNS.Listen != "127.0.0.1:5454" {
		t.Errorf("DNS: %v %q", cfg.DNS.Enabled, cfg.DNS.Listen)
	}
	if !cfg.Tun.Enabled {
		t.Error("TUN should be enabled")
	}
	if !cfg.Scribe.Enabled || cfg.Scribe.Listen != "0.0.0.0:9090" {
		t.Errorf("Scribe: %v %q", cfg.Scribe.Enabled, cfg.Scribe.Listen)
	}
	if !cfg.Exit.Enabled {
		t.Error("Exit should be enabled")
	}
	if len(cfg.Exit.CIDRs) != 2 || cfg.Exit.CIDRs[0] != "10.0.0.0/8" || cfg.Exit.CIDRs[1] != "192.168.0.0/16" {
		t.Errorf("Exit.CIDRs = %v, want [10.0.0.0/8 192.168.0.0/16]", cfg.Exit.CIDRs)
	}
	if cfg.Tun.CIDR != "172.16.0.0/12" {
		t.Errorf("Tun.CIDR = %q, want 172.16.0.0/12", cfg.Tun.CIDR)
	}
}

func TestApplyFlagsCATokenFallback(t *testing.T) {
	cfg := config.Defaults()

	// When --ca is set but --ca-token is empty, should fall back to --token.
	cli.ApplyFlags(cfg,
		"", "", "", "", "", "", "shared-token",
		true, "",
		false, "",
		false, "",
		false, 0, false,
		false, "",
		false, "", "",
	)

	if cfg.CA.JoinToken != "shared-token" {
		t.Errorf("CA.JoinToken should fall back to --token, got %q", cfg.CA.JoinToken)
	}
}

func TestApplyFlagsNoOverrideDefaults(t *testing.T) {
	cfg := config.Defaults()
	origAddr := cfg.Node.Addr

	// Empty flags should not override defaults.
	cli.ApplyFlags(cfg,
		"", "", "", "", "", "", "",
		false, "",
		false, "",
		false, "",
		false, 0, false,
		false, "",
		false, "", "",
	)

	if cfg.Node.Addr != origAddr {
		t.Errorf("Addr should not change with empty flag, got %q want %q", cfg.Node.Addr, origAddr)
	}
}

func TestResolveDataDir(t *testing.T) {
	// Explicit dir takes precedence.
	dir := cli.ResolveDataDir("/explicit")
	if dir != "/explicit" {
		t.Errorf("explicit dir: got %q", dir)
	}

	// Empty falls back to default.
	dir = cli.ResolveDataDir("")
	if dir == "" {
		t.Error("should not return empty")
	}
}

func TestSocketPath(t *testing.T) {
	// With explicit --socket flag.
	path := cli.SocketPath([]string{"--socket", "/tmp/test.sock"})
	if path != "/tmp/test.sock" {
		t.Errorf("explicit socket: got %q", path)
	}

	// Default should end with pulse.sock.
	path = cli.SocketPath([]string{})
	if path == "" {
		t.Error("should not return empty")
	}
}
