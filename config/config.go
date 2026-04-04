package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Node      NodeConfig      `toml:"node"`
	Bootstrap BootstrapConfig `toml:"bootstrap"`
	CA        CAConfig        `toml:"ca"`
	Join      JoinConfig      `toml:"join"`
	SOCKS     SOCKSConfig     `toml:"socks"`
	DNS       DNSConfig       `toml:"dns"`
	Exit      ExitConfig      `toml:"exit"`
	Scribe    ScribeConfig    `toml:"scribe"`
	Tun       TunConfig       `toml:"tun"`
	Persist   PersistConfig   `toml:"persist"`
	Control   ControlConfig   `toml:"control"`
}

type NodeConfig struct {
	Addr      string `toml:"addr"`         // advertised address (gossipped to peers)
	Listen    string `toml:"listen"`       // actual bind address (defaults to addr if empty)
	TCPListen string `toml:"tcp_listen"`
	DataDir   string `toml:"data_dir"`
	NetworkID string `toml:"network_id"`   // network isolation ID (peers with different IDs are rejected)
	LogLevel  string `toml:"log_level"`    // debug, info, warn, error (default: info)
}

type BootstrapConfig struct {
	Peers     []string `toml:"peers"`
	DNSDomain string   `toml:"dns_domain"` // e.g. "yourdomain.com" → queries _pulse.yourdomain.com TXT
}

type CAConfig struct {
	Enabled   bool   `toml:"enabled"`
	DataDir   string `toml:"data_dir"`
	JoinToken string `toml:"join_token"`
}

type JoinConfig struct {
	RelayAddr string `toml:"relay_addr"`
	Token     string `toml:"token"`
}

type ControlConfig struct {
	Socket string `toml:"socket"` // Unix socket path, default ~/.pulse/pulse.sock
}

type SOCKSConfig struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"` // default ":1080"
}

type DNSConfig struct {
	Enabled  bool   `toml:"enabled"`
	Listen   string `toml:"listen"` // default "127.0.0.1:5353"
	Services []struct {
		Name     string `toml:"name"`
		Port     uint16 `toml:"port"`
		Priority uint16 `toml:"priority"`
	} `toml:"service"`
}

type ExitConfig struct {
	Enabled    bool     `toml:"enabled"`
	CIDRs      []string `toml:"cidrs"`       // CIDRs this node will exit (advertised in gossip)
	RoutesFile string   `toml:"routes_file"` // client-side CIDR route table (JSON)
}

type ScribeConfig struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"` // HTTP API listen address, default "127.0.0.1:8080"
}

type TunConfig struct {
	Enabled bool   `toml:"enabled"`
	Name    string `toml:"name"` // interface name, default "pulse0"
	CIDR    string `toml:"cidr"` // mesh IP range, default "10.100.0.0/16"
}

type PersistConfig struct {
	Enabled  bool `toml:"enabled"`   // persist peer table to disk (default true)
	Interval int  `toml:"interval"`  // save interval in seconds (default 60)
}

func Load(path string) (*Config, error) {
	cfg := &Config{}
	cfg.Node.Addr = ":8443"
	cfg.Node.TCPListen = ":7000"
	cfg.Node.DataDir = defaultDataDir()
	cfg.CA.DataDir = defaultDataDir() + "/ca"
	cfg.SOCKS.Listen = ":1080"
	cfg.DNS.Listen = "127.0.0.1:5353"
	cfg.Exit.RoutesFile = defaultDataDir() + "/routes.json"
	cfg.Scribe.Listen = "127.0.0.1:8080"
	cfg.Tun.Name = "pulse0"
	cfg.Tun.CIDR = "10.100.0.0/16"
	cfg.Persist.Enabled = true
	cfg.Persist.Interval = 60
	cfg.Control.Socket = defaultDataDir() + "/pulse.sock"

	if path != "" {
		if _, err := toml.DecodeFile(path, cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".pulse"
	}
	return home + "/.pulse"
}
