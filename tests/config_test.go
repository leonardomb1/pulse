package tests

import (
	"github.com/leonardomb1/pulse/config"
	"testing"
)

func TestConfigDefaults(t *testing.T) {
	cfg := config.Defaults()

	if cfg.Node.Addr != ":8443" {
		t.Errorf("Addr = %q, want :8443", cfg.Node.Addr)
	}
	if cfg.Node.TCPListen != ":7000" {
		t.Errorf("TCPListen = %q, want :7000", cfg.Node.TCPListen)
	}
	if cfg.Tun.Name != "pulse0" {
		t.Errorf("Tun.Name = %q, want pulse0", cfg.Tun.Name)
	}
	if cfg.Tun.CIDR != "10.100.0.0/16" {
		t.Errorf("Tun.CIDR = %q, want 10.100.0.0/16", cfg.Tun.CIDR)
	}
	if !cfg.Persist.Enabled {
		t.Error("Persist should be enabled by default")
	}
	if cfg.Node.DataDir == "" {
		t.Error("DataDir should not be empty")
	}
}
