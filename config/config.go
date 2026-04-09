package config

import "os"

// DefaultMeshCIDR is the default mesh IP range used when no --mesh-cidr is specified.
const DefaultMeshCIDR = "10.100.0.0/16"

type Config struct {
	Node      NodeConfig
	Bootstrap BootstrapConfig
	CA        CAConfig
	Join      JoinConfig
	SOCKS     SOCKSConfig
	DNS       DNSConfig
	Exit      ExitConfig
	Scribe    ScribeConfig
	Tun       TunConfig
	Persist   PersistConfig
	Control   ControlConfig
}

type NodeConfig struct {
	Addr      string
	Listen    string
	TCPListen string
	DataDir   string
	NetworkID string
	LogLevel  string
}

type BootstrapConfig struct {
	Peers     []string
	DNSDomain string
}

type CAConfig struct {
	Enabled   bool
	DataDir   string
	JoinToken string
}

type JoinConfig struct {
	RelayAddr string
	Token     string
}

type ControlConfig struct {
	Socket string
}

type SOCKSConfig struct {
	Enabled bool
	Listen  string
}

type DNSConfig struct {
	Enabled  bool
	Listen   string
	Services []struct {
		Name     string
		Port     uint16
		Priority uint16
	}
}

type ExitConfig struct {
	Enabled    bool
	CIDRs      []string
	RoutesFile string
}

type ScribeConfig struct {
	Enabled bool
	Listen  string
}

type TunConfig struct {
	Enabled bool
	Name    string
	CIDR    string
	FEC     bool
	Queues  int // multi-queue TUN readers (default 1, set higher for >1Gbps)
}

type PersistConfig struct {
	Enabled  bool
	Interval int
}

// Defaults returns a Config with sensible defaults.
func Defaults() *Config {
	return &Config{
		Node: NodeConfig{
			Addr:      ":8443",
			TCPListen: ":7000",
			DataDir:   defaultDataDir(),
		},
		CA: CAConfig{
			DataDir: defaultDataDir() + "/ca",
		},
		SOCKS: SOCKSConfig{
			Listen: ":1080",
		},
		DNS: DNSConfig{
			Listen: "127.0.0.1:5353",
		},
		Exit: ExitConfig{
			RoutesFile: defaultDataDir() + "/routes.json",
		},
		Scribe: ScribeConfig{
			Listen: "127.0.0.1:8080",
		},
		Tun: TunConfig{
			Name:   "pulse0",
			CIDR:   DefaultMeshCIDR,
			Queues: 1,
		},
		Persist: PersistConfig{
			Enabled:  true,
			Interval: 60,
		},
		Control: ControlConfig{
			Socket: defaultDataDir() + "/pulse.sock",
		},
	}
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".pulse"
	}
	return home + "/.pulse"
}
