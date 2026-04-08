package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/leonardomb1/pulse/config"
	"github.com/leonardomb1/pulse/node"
)

// NodeFlags registers all flags for running a node on the given FlagSet.
func NodeFlags(fs *flag.FlagSet) (
	wsAddr, listenAddr, tcpAddr, dataDir, networkID, joinAddr, joinToken *string,
	caEnabled *bool, caToken *string,
	socksEnabled *bool, socksListen *string,
	dnsEnabled *bool, dnsListen *string,
	tunEnabled *bool, fecEnabled *bool,
	scribeEnabled *bool, scribeListen *string,
	exitEnabled *bool, exitCIDRs *string,
	meshCIDR *string,
) {
	dataDir = fs.String("data-dir", "", "persistent data directory (default ~/.pulse)")
	wsAddr = fs.String("addr", "", "advertised address (gossipped to peers)")
	listenAddr = fs.String("listen", "", "bind address (default: same as --addr)")
	tcpAddr = fs.String("tcp", "", "TCP tunnel listener address")
	networkID = fs.String("network", "", "network ID for isolation (peers with different IDs are rejected)")
	joinAddr = fs.String("join", "", "CA relay address (bootstrap on startup if not yet joined)")
	joinToken = fs.String("token", "", "join token")
	caEnabled = fs.Bool("ca", false, "enable certificate authority")
	caToken = fs.String("ca-token", "", "join token the CA accepts (defaults to --token)")
	socksEnabled = fs.Bool("socks", false, "enable SOCKS5 proxy")
	socksListen = fs.String("socks-listen", "", "SOCKS5 listen address (default 127.0.0.1:1080)")
	dnsEnabled = fs.Bool("dns", false, "enable DNS server for .pulse")
	dnsListen = fs.String("dns-listen", "", "DNS listen address (default 127.0.0.1:5353)")
	tunEnabled = fs.Bool("tun", false, "enable TUN interface (Linux only)")
	fecEnabled = fs.Bool("fec", false, "enable FEC on TUN pipes (lossy links)")
	scribeEnabled = fs.Bool("scribe", false, "enable scribe (control plane)")
	scribeListen = fs.String("scribe-listen", "", "scribe HTTP API address (default 127.0.0.1:8080)")
	exitEnabled = fs.Bool("exit", false, "enable exit node")
	exitCIDRs = fs.String("exit-cidrs", "", "comma-separated CIDRs this exit node advertises (e.g. 0.0.0.0/0)")
	meshCIDR = fs.String("mesh-cidr", "", "mesh IP range (default 10.100.0.0/16)")
	return
}

// ApplyFlags merges CLI flags into the loaded config. Flags take precedence.
func ApplyFlags(cfg *config.Config,
	wsAddr, listenAddr, tcpAddr, dataDir, networkID, joinAddr, joinToken string,
	caEnabled bool, caToken string,
	socksEnabled bool, socksListen string,
	dnsEnabled bool, dnsListen string,
	tunEnabled bool, fecEnabled bool,
	scribeEnabled bool, scribeListen string,
	exitEnabled bool, exitCIDRs string,
	meshCIDR string,
) {
	if dataDir != "" {
		cfg.Node.DataDir = dataDir
		cfg.CA.DataDir = dataDir + "/ca"
		cfg.Exit.RoutesFile = dataDir + "/routes.json"
		cfg.Control.Socket = dataDir + "/pulse.sock"
	}
	if wsAddr != "" {
		cfg.Node.Addr = wsAddr
	}
	if listenAddr != "" {
		cfg.Node.Listen = listenAddr
	}
	if tcpAddr != "" {
		cfg.Node.TCPListen = tcpAddr
	}
	if networkID != "" {
		cfg.Node.NetworkID = networkID
	}
	if joinAddr != "" {
		cfg.Join.RelayAddr = joinAddr
	}
	if joinToken != "" {
		cfg.Join.Token = joinToken
	}
	if caEnabled {
		cfg.CA.Enabled = true
		tok := caToken
		if tok == "" {
			tok = joinToken
		}
		if tok != "" {
			cfg.CA.JoinToken = tok
		}
	}
	if socksEnabled {
		cfg.SOCKS.Enabled = true
	}
	if socksListen != "" {
		cfg.SOCKS.Listen = socksListen
	}
	if dnsEnabled {
		cfg.DNS.Enabled = true
	}
	if dnsListen != "" {
		cfg.DNS.Listen = dnsListen
	}
	if tunEnabled {
		cfg.Tun.Enabled = true
	}
	if fecEnabled {
		cfg.Tun.FEC = true
	}
	if scribeEnabled {
		cfg.Scribe.Enabled = true
	}
	if scribeListen != "" {
		cfg.Scribe.Listen = scribeListen
	}
	if exitEnabled {
		cfg.Exit.Enabled = true
	}
	if exitCIDRs != "" {
		cfg.Exit.CIDRs = strings.Split(exitCIDRs, ",")
	}
	if meshCIDR != "" {
		cfg.Tun.CIDR = meshCIDR
	}
}

// ApplyNodeState loads state.dat and applies fields not explicitly set via CLI flags.
func ApplyNodeState(cfg *config.Config, dataDir string, explicitFlags map[string]bool) {
	snc, err := node.LoadNodeState(dataDir)
	if err != nil || snc == nil {
		return
	}
	// Verify signature would go here once CA pubkey is available at this stage.
	// For now, trust the local file (it was written by a verified scribe push).
	nc := snc.Config

	if !explicitFlags["tun"] && nc.TunEnabled {
		cfg.Tun.Enabled = true
	}
	if !explicitFlags["socks"] && nc.SocksEnabled {
		cfg.SOCKS.Enabled = true
	}
	if !explicitFlags["dns"] && nc.DNSEnabled {
		cfg.DNS.Enabled = true
	}
	if !explicitFlags["exit"] && nc.ExitEnabled {
		cfg.Exit.Enabled = true
	}
	if !explicitFlags["exit-cidrs"] && len(nc.ExitCIDRs) > 0 {
		cfg.Exit.CIDRs = nc.ExitCIDRs
	}
	if !explicitFlags["fec"] && nc.FECEnabled {
		cfg.Tun.FEC = true
	}
	if !explicitFlags["mesh-cidr"] && nc.MeshCIDR != "" {
		cfg.Tun.CIDR = nc.MeshCIDR
	}
	if !explicitFlags["log-level"] && nc.LogLevel != "" {
		cfg.Node.LogLevel = nc.LogLevel
	}
	log.Printf("state: loaded signed config v%d from state.dat", nc.Version)
}

// RunNode starts a relay node. Called when pulse is run with no subcommand.
// NodeVersion is set by main.go from ldflags.
var NodeVersion = "dev"

func RunNode(args []string) {
	fs := flag.NewFlagSet("pulse", flag.ExitOnError)
	wsAddr, listenAddr, tcpAddr, dataDir, networkID, joinAddr, joinToken,
		caEnabled, caToken,
		socksEnabled, socksListen,
		dnsEnabled, dnsListen,
		tunEnabled, fecEnabled,
		scribeEnabled, scribeListen,
		exitEnabled, exitCIDRs,
		meshCIDR := NodeFlags(fs)
	logLevelFlag := fs.String("log-level", "", "log level: debug, info, warn, error (default: info)")
	_ = fs.Parse(args)

	cfg := config.Defaults()
	ApplyFlags(cfg, *wsAddr, *listenAddr, *tcpAddr, *dataDir, *networkID, *joinAddr, *joinToken,
		*caEnabled, *caToken, *socksEnabled, *socksListen,
		*dnsEnabled, *dnsListen, *tunEnabled, *fecEnabled, *scribeEnabled, *scribeListen, *exitEnabled, *exitCIDRs, *meshCIDR)

	// Load signed state from scribe (if exists). CLI flags take precedence.
	explicit := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	ApplyNodeState(cfg, cfg.Node.DataDir, explicit)

	ll := *logLevelFlag
	if ll == "" {
		ll = cfg.Node.LogLevel
	}
	if ll != "" {
		node.SetLogLevel(node.ParseLogLevel(ll))
	}

	cfg.Bootstrap.Peers = append(cfg.Bootstrap.Peers, fs.Args()...)

	// Join flow (first-time bootstrap).
	addr := cfg.Join.RelayAddr
	tok := cfg.Join.Token
	if addr != "" {
		caCertPath := filepath.Join(cfg.Node.DataDir, "ca.crt")
		if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
			if err := DoJoin(cfg, addr, tok); err != nil {
				log.Printf("join: %v — will retry in background after starting", err)
			} else {
				log.Println("join successful — starting node")
			}
		}
	}

	// CA setup.
	var ca *node.CA
	if cfg.CA.Enabled {
		caDir := cfg.CA.DataDir
		var err error
		ca, err = LoadOrInitCA(caDir, cfg.CA.JoinToken)
		if err != nil {
			log.Fatalf("init CA: %v", err)
		}
		log.Printf("CA loaded from %s", caDir)
	}

	n, err := node.New(cfg, ca, NodeVersion)
	if err != nil {
		log.Fatalf("init node: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if addr != "" {
		caCertPath := filepath.Join(cfg.Node.DataDir, "ca.crt")
		if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
			go func() {
				backoff := 5 * time.Second
				for {
					select {
					case <-ctx.Done():
						return
					case <-time.After(backoff):
					}
					if err := DoJoin(cfg, addr, tok); err != nil {
						log.Printf("join retry: %v", err)
						if backoff < 60*time.Second {
							backoff *= 2
						}
						continue
					}
					log.Println("join successful — reloading identity")
					if err := n.ReloadIdentity(); err != nil {
						log.Printf("reload identity: %v", err)
					}
					return
				}
			}()
		}
	}

	if err := n.Run(ctx); err != nil {
		log.Fatalf("run: %v", err)
	}
}

// DoJoin performs the join flow against a relay CA.
func DoJoin(cfg *config.Config, relayAddr, token string) error {
	if token == "" {
		return fmt.Errorf("--token is required for joining")
	}
	identity, err := node.LoadOrCreateIdentity(cfg.Node.DataDir)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	req := node.JoinRequest{
		PublicKey: identity.PublicKey,
		Token:     token,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := node.Join(ctx, relayAddr, req)
	if err != nil {
		return err
	}
	if err := node.StoreJoinResult(cfg.Node.DataDir, *resp); err != nil {
		return fmt.Errorf("store join result: %w", err)
	}
	log.Printf("joined as node %s", resp.NodeID)
	return nil
}

// LoadOrInitCA loads or creates a CA from the given directory.
func LoadOrInitCA(dir, token string) (*node.CA, error) {
	caCertPath := filepath.Join(dir, "ca.crt")
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		log.Printf("no existing CA found in %s — generating new CA keypair", dir)
		return node.InitCA(dir, token)
	}
	return node.LoadCA(dir, token)
}

// ResolveDataDir resolves the data directory from flags or defaults.
func ResolveDataDir(dataDir string) string {
	if dataDir != "" {
		return dataDir
	}
	return config.Defaults().Node.DataDir
}
