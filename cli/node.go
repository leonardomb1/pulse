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

// FlagValues holds all the CLI flag values for running a node.
type FlagValues struct {
	Addr          string
	Listen        string
	TCP           string
	DataDir       string
	NetworkID     string
	JoinAddr      string
	JoinToken     string
	CAEnabled     bool
	CAToken       string
	SOCKSEnabled  bool
	SOCKSListen   string
	DNSEnabled    bool
	DNSListen     string
	TunEnabled    bool
	TunQueues     int
	FECEnabled    bool
	ScribeEnabled bool
	ScribeListen  string
	ExitEnabled   bool
	ExitCIDRs     string
	MeshCIDR      string
	IOURing       bool
}

// NodeFlags registers all flags for running a node on the given FlagSet.
func NodeFlags(fs *flag.FlagSet) *FlagValues {
	f := &FlagValues{}
	fs.StringVar(&f.DataDir, "data-dir", "", "persistent data directory (default ~/.pulse)")
	fs.StringVar(&f.Addr, "addr", "", "advertised address (gossipped to peers)")
	fs.StringVar(&f.Listen, "listen", "", "bind address (default: same as --addr)")
	fs.StringVar(&f.TCP, "tcp", "", "TCP tunnel listener address")
	fs.StringVar(&f.NetworkID, "network", "", "network ID for isolation (peers with different IDs are rejected)")
	fs.StringVar(&f.JoinAddr, "join", "", "CA relay address (bootstrap on startup if not yet joined)")
	fs.StringVar(&f.JoinToken, "token", "", "join token")
	fs.BoolVar(&f.CAEnabled, "ca", false, "enable certificate authority")
	fs.StringVar(&f.CAToken, "ca-token", "", "join token the CA accepts (defaults to --token)")
	fs.BoolVar(&f.SOCKSEnabled, "socks", false, "enable SOCKS5 proxy")
	fs.StringVar(&f.SOCKSListen, "socks-listen", "", "SOCKS5 listen address (default 127.0.0.1:1080)")
	fs.BoolVar(&f.DNSEnabled, "dns", false, "enable DNS server for .pulse")
	fs.StringVar(&f.DNSListen, "dns-listen", "", "DNS listen address (default 127.0.0.1:5353)")
	fs.BoolVar(&f.TunEnabled, "tun", false, "enable TUN interface (Linux only)")
	fs.IntVar(&f.TunQueues, "tun-queues", 0, "TUN multi-queue readers (default 1, set to CPU count for high throughput)")
	fs.BoolVar(&f.FECEnabled, "fec", false, "enable FEC on TUN pipes (lossy links)")
	fs.BoolVar(&f.ScribeEnabled, "scribe", false, "enable scribe (control plane)")
	fs.StringVar(&f.ScribeListen, "scribe-listen", "", "scribe HTTP API address (default 127.0.0.1:8080)")
	fs.BoolVar(&f.ExitEnabled, "exit", false, "enable exit node")
	fs.StringVar(&f.ExitCIDRs, "exit-cidrs", "", "comma-separated CIDRs this exit node advertises (e.g. 0.0.0.0/0)")
	fs.StringVar(&f.MeshCIDR, "mesh-cidr", "", "mesh IP range (default 10.100.0.0/16)")
	fs.BoolVar(&f.IOURing, "iouring", false, "use io_uring for TUN I/O (Linux ≥5.1, auto-fallback)")
	return f
}

// ApplyFlags merges CLI flags into the loaded config. Flags take precedence.
func ApplyFlags(cfg *config.Config, f *FlagValues) {
	if f.DataDir != "" {
		cfg.Node.DataDir = f.DataDir
		cfg.CA.DataDir = f.DataDir + "/ca"
		cfg.Exit.RoutesFile = f.DataDir + "/routes.json"
		cfg.Control.Socket = f.DataDir + "/pulse.sock"
	}
	if f.Addr != "" {
		cfg.Node.Addr = f.Addr
	}
	if f.Listen != "" {
		cfg.Node.Listen = f.Listen
	}
	if f.TCP != "" {
		cfg.Node.TCPListen = f.TCP
	}
	if f.NetworkID != "" {
		cfg.Node.NetworkID = f.NetworkID
	}
	if f.JoinAddr != "" {
		cfg.Join.RelayAddr = f.JoinAddr
	}
	if f.JoinToken != "" {
		cfg.Join.Token = f.JoinToken
	}
	if f.CAEnabled {
		cfg.CA.Enabled = true
		tok := f.CAToken
		if tok == "" {
			tok = f.JoinToken
		}
		if tok != "" {
			cfg.CA.JoinToken = tok
		}
	}
	if f.SOCKSEnabled {
		cfg.SOCKS.Enabled = true
	}
	if f.SOCKSListen != "" {
		cfg.SOCKS.Listen = f.SOCKSListen
	}
	if f.DNSEnabled {
		cfg.DNS.Enabled = true
	}
	if f.DNSListen != "" {
		cfg.DNS.Listen = f.DNSListen
	}
	if f.TunEnabled {
		cfg.Tun.Enabled = true
	}
	if f.TunQueues > 0 {
		cfg.Tun.Queues = f.TunQueues
	}
	if f.FECEnabled {
		cfg.Tun.FEC = true
	}
	if f.ScribeEnabled {
		cfg.Scribe.Enabled = true
	}
	if f.ScribeListen != "" {
		cfg.Scribe.Listen = f.ScribeListen
	}
	if f.ExitEnabled {
		cfg.Exit.Enabled = true
	}
	if f.ExitCIDRs != "" {
		cfg.Exit.CIDRs = strings.Split(f.ExitCIDRs, ",")
	}
	if f.MeshCIDR != "" {
		cfg.Tun.CIDR = f.MeshCIDR
	}
	if f.IOURing {
		cfg.Tun.IOURing = true
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
	if !explicitFlags["tun-queues"] && nc.TunQueues > 0 {
		cfg.Tun.Queues = nc.TunQueues
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
	if !explicitFlags["iouring"] && nc.IOURing {
		cfg.Tun.IOURing = true
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
	f := NodeFlags(fs)
	logLevelFlag := fs.String("log-level", "", "log level: debug, info, warn, error (default: info)")
	_ = fs.Parse(args)

	cfg := config.Defaults()
	ApplyFlags(cfg, f)

	// Load signed state from scribe (if exists). CLI flags take precedence.
	explicit := make(map[string]bool)
	fs.Visit(func(fl *flag.Flag) { explicit[fl.Name] = true })
	ApplyNodeState(cfg, cfg.Node.DataDir, explicit)

	ll := *logLevelFlag
	if ll == "" {
		ll = cfg.Node.LogLevel
	}
	if ll != "" {
		node.SetLogLevel(node.ParseLogLevel(ll))
	}

	// Set up rotating log file (daemon writes here, pulse logs reads it).
	logPath := filepath.Join(cfg.Node.DataDir, "pulse.log")
	_ = os.MkdirAll(cfg.Node.DataDir, 0700)
	if err := node.SetupLogFile(logPath); err != nil {
		log.Printf("warning: could not set up log file: %v", err)
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
