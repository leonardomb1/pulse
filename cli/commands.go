package cli

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/leonardomb1/pulse/client"
	"github.com/leonardomb1/pulse/config"
	"github.com/leonardomb1/pulse/node"
	"github.com/leonardomb1/pulse/tui"
)

func RunStart(args []string) {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("start: resolve executable: %v", err)
	}
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}
	logPath := filepath.Join(config.Defaults().Node.DataDir, "pulse.log")
	fmt.Printf("pulse started (pid %d, logs: %s)\n", cmd.Process.Pid, logPath)
}

func RunStop(args []string) {
	sock := SocketPath(args)
	if _, err := CtrlDo(sock, map[string]string{"cmd": "stop"}); err != nil {
		log.Fatal(err)
	}
	fmt.Println("pulse stopped")
}

func RunStatus(args []string) {
	sock := SocketPath(args)
	resp, err := CtrlDo(sock, map[string]string{"cmd": "status"})
	if err != nil {
		log.Fatal(err)
	}

	var self string
	_ = json.Unmarshal(resp["self"], &self)
	var meshCIDR string
	_ = json.Unmarshal(resp["mesh_cidr"], &meshCIDR)
	if meshCIDR == "" {
		meshCIDR = config.DefaultMeshCIDR
	}
	selfMeshIP := node.MeshIPFromNodeIDWithCIDR(self, meshCIDR)

	var networkID string
	_ = json.Unmarshal(resp["network_id"], &networkID)
	netLabel := ""
	if networkID != "" {
		netLabel = fmt.Sprintf(" network: %s", networkID)
	}
	fmt.Printf("Node: %s (mesh: %s)%s\n\n", self, selfMeshIP, netLabel)

	var peers []node.PeerEntry
	_ = json.Unmarshal(resp["peers"], &peers)

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NODE ID\tNAME\tADDR\tMESH IP\tLINK\tLATENCY\tLOSS%\tHOPS\tVERSION\tROLES\tTAGS\tLAST SEEN")
	for _, p := range peers {
		meshIP := p.MeshIP
		if meshIP == "" {
			meshIP = node.MeshIPFromNodeIDWithCIDR(p.NodeID, meshCIDR).String()
		}
		linkType := "-"
		if p.LinkType != "" {
			linkType = p.LinkType
		}
		latency := "-"
		if p.LatencyMS > 0 && p.LatencyMS < 1e15 {
			latency = fmt.Sprintf("%.1fms", p.LatencyMS)
		}
		loss := fmt.Sprintf("%.0f%%", p.LossRate*100)
		lastSeen := "-"
		if !p.LastSeen.IsZero() {
			lastSeen = time.Since(p.LastSeen).Round(time.Second).String() + " ago"
		}
		roles := "-"
		if p.IsCA || p.IsScribe || p.IsExit {
			r := ""
			if p.IsCA {
				r += "CA "
			}
			if p.IsScribe {
				r += "scribe "
			}
			if p.IsExit {
				r += "exit"
			}
			roles = r
		}
		name := p.Name
		if name == "" {
			name = "-"
		}
		tags := "-"
		if len(p.Tags) > 0 {
			tags = strings.Join(p.Tags, ",")
		}
		ver := p.Version
		if ver == "" {
			ver = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			p.NodeID, name, p.Addr, meshIP, linkType, latency, loss, p.HopCount, ver, roles, tags, lastSeen)
	}
	_ = tw.Flush()
}

func RunStats(args []string) {
	sock := SocketPath(args)
	cmd := map[string]interface{}{"cmd": "peer-stats"}
	// If a node ID is provided as positional arg, filter to that node.
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		cmd["node_id"] = fs.Arg(0)
	}
	resp, err := CtrlDo(sock, cmd)
	if err != nil {
		log.Fatal(err)
	}
	b, _ := json.MarshalIndent(json.RawMessage(resp["snapshots"]), "", "  ")
	if b != nil && string(b) != "null" {
		fmt.Println(string(b))
		return
	}
	b, _ = json.MarshalIndent(json.RawMessage(resp["latest"]), "", "  ")
	fmt.Println(string(b))
}

func RunEvents(args []string) {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	sock := fs.String("socket", "", "control socket path")
	eventType := fs.String("type", "", "filter by event type")
	nodeFilter := fs.String("node", "", "filter by node ID")
	since := fs.String("since", "", "show events since (RFC3339 or duration like 1h)")
	_ = fs.Parse(args)

	path := SocketPath([]string{"--socket", *sock})
	cmd := map[string]interface{}{"cmd": "events"}
	if *eventType != "" {
		cmd["event_type"] = *eventType
	}
	if *nodeFilter != "" {
		cmd["node_id"] = *nodeFilter
	}
	if *since != "" {
		// Try parsing as duration first (e.g. "1h"), then as RFC3339.
		if d, err := time.ParseDuration(*since); err == nil {
			cmd["since"] = time.Now().Add(-d).Format(time.RFC3339)
		} else {
			cmd["since"] = *since
		}
	}
	resp, err := CtrlDo(path, cmd)
	if err != nil {
		log.Fatal(err)
	}
	var events []node.EventEntry
	_ = json.Unmarshal(resp["events"], &events)
	for _, e := range events {
		line, _ := json.Marshal(e)
		fmt.Println(string(line))
	}
}

func RunLogs(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	follow := fs.Bool("f", false, "follow log output")
	lines := fs.Int("n", 50, "number of lines to show")
	_ = fs.Parse(args)

	logPath := filepath.Join(config.Defaults().Node.DataDir, "pulse.log")

	if *follow {
		// tail -f behavior: print last N lines then follow.
		tailFollow(logPath, *lines)
	} else {
		tailLines(logPath, *lines)
	}
}

func tailLines(path string, n int) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	start := len(lines) - n
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start:] {
		fmt.Println(l)
	}
}

func tailFollow(path string, n int) {
	// Print last N lines first.
	tailLines(path, n)

	// Then follow.
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	_, _ = f.Seek(0, io.SeekEnd)

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		fmt.Print(line)
	}
}

func RunID(args []string) {
	fs := flag.NewFlagSet("id", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory (default ~/.pulse)")
	_ = fs.Parse(args)

	dir := ResolveDataDir(*dataDir)
	identity, err := node.LoadOrCreateIdentity(dir)
	if err != nil {
		log.Fatalf("load identity: %v", err)
	}
	// Try to get active CIDR from running daemon.
	meshCIDR := config.DefaultMeshCIDR
	sock := filepath.Join(dir, "pulse.sock")
	if resp, err := CtrlDo(sock, map[string]string{"cmd": "mesh-cidr"}); err == nil {
		var cidr string
		_ = json.Unmarshal(resp["mesh_cidr"], &cidr)
		if cidr != "" {
			meshCIDR = cidr
		}
	}
	meshIP := node.MeshIPFromNodeIDWithCIDR(identity.NodeID, meshCIDR)
	fmt.Printf("%s (mesh: %s)\n", identity.NodeID, meshIP)
}

func RunCert(args []string) {
	fs := flag.NewFlagSet("cert", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory (default ~/.pulse)")
	_ = fs.Parse(args)

	dir := ResolveDataDir(*dataDir)

	certPEM, err := os.ReadFile(filepath.Join(dir, "identity.crt"))
	if err != nil {
		log.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatal("no PEM block in identity.crt")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("parse cert: %v", err)
	}

	remaining := time.Until(cert.NotAfter)
	status := "valid"
	if remaining <= 0 {
		status = "EXPIRED"
	} else if remaining < 30*24*time.Hour {
		status = fmt.Sprintf("expiring soon (%s remaining)", remaining.Round(time.Hour))
	}

	fmt.Printf("Subject:   %s\n", cert.Subject.CommonName)
	fmt.Printf("Issuer:    %s\n", cert.Issuer.CommonName)
	fmt.Printf("NotBefore: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("NotAfter:  %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("Remaining: %s\n", remaining.Round(time.Hour))
	fmt.Printf("Serial:    %s\n", cert.SerialNumber.Text(16))
	fmt.Printf("Status:    %s\n", status)

	caCertPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err == nil {
		caBlock, _ := pem.Decode(caCertPEM)
		if caBlock != nil {
			caCert, err := x509.ParseCertificate(caBlock.Bytes)
			if err == nil {
				fmt.Printf("\nCA:\n")
				fmt.Printf("  Subject:  %s\n", caCert.Subject.CommonName)
				fmt.Printf("  NotAfter: %s\n", caCert.NotAfter.Format(time.RFC3339))
			}
		}
	}
}

func RunMeshIP(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: pulse mesh-ip <node-id> <ip>")
		os.Exit(1)
	}
	sock := SocketPath(args[2:])
	if _, err := CtrlDo(sock, map[string]string{
		"cmd": "mesh-ip-set", "node_id": args[0], "mesh_ip": args[1],
	}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("mesh IP %s → %s\n", args[0], args[1])
}

// EncodeJoinCode encodes relay address, token, and network ID into a single string.
// Format: pls_<base64(json)>
func EncodeJoinCode(relay, token, network string) string {
	data := map[string]string{"r": relay, "t": token}
	if network != "" {
		data["n"] = network
	}
	b, _ := json.Marshal(data)
	return "pls_" + base64.RawURLEncoding.EncodeToString(b)
}

// DecodeJoinCode decodes a pls_ join code into relay, token, network.
func DecodeJoinCode(code string) (relay, token, network string, err error) {
	if !strings.HasPrefix(code, "pls_") {
		return "", "", "", fmt.Errorf("invalid join code (must start with pls_)")
	}
	b, err := base64.RawURLEncoding.DecodeString(code[4:])
	if err != nil {
		return "", "", "", fmt.Errorf("invalid join code: %w", err)
	}
	var data map[string]string
	if err := json.Unmarshal(b, &data); err != nil {
		return "", "", "", fmt.Errorf("invalid join code: %w", err)
	}
	return data["r"], data["t"], data["n"], nil
}

func RunInvite(args []string) {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	sock := fs.String("socket", "", "control socket path")
	network := fs.String("network", "", "network ID to include")
	_ = fs.Parse(args)

	path := SocketPath([]string{"--socket", *sock})

	// Get relay addr from status.
	resp, err := CtrlDo(path, map[string]string{"cmd": "status"})
	if err != nil {
		log.Fatal(err)
	}
	var peers []node.PeerEntry
	_ = json.Unmarshal(resp["peers"], &peers)

	// Find the CA node's address.
	relayAddr := ""
	for _, p := range peers {
		if p.IsCA && p.Addr != "" {
			relayAddr = p.Addr
			break
		}
	}
	if relayAddr == "" {
		log.Fatal("no CA node with an address found in the mesh")
	}

	// Get token.
	resp, err = CtrlDo(path, map[string]string{"cmd": "token"})
	if err != nil {
		log.Fatal(err)
	}
	var token string
	_ = json.Unmarshal(resp["token"], &token)
	if token == "" {
		log.Fatal("no token available (is this node the CA?)")
	}

	code := EncodeJoinCode(relayAddr, token, *network)
	fmt.Println(code)
}

func RunJoin(args []string) {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	token := fs.String("token", "", "join token (required)")
	dataDir := fs.String("data-dir", "", "data directory (default ~/.pulse)")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse join <relay-addr> --token <token>")
		_, _ = fmt.Fprintln(os.Stderr, "       pulse join <pls_code>")
		os.Exit(1)
	}

	relayAddr := fs.Arg(0)

	// Check if the argument is a join code.
	if strings.HasPrefix(relayAddr, "pls_") {
		r, t, n, err := DecodeJoinCode(relayAddr)
		if err != nil {
			log.Fatalf("invalid join code: %v", err)
		}
		relayAddr = r
		if *token == "" {
			*token = t
		}
		// Network ID from the code is informational — applied when starting the node.
		if n != "" {
			fmt.Printf("network: %s\n", n)
		}
	}
	dir := ResolveDataDir(*dataDir)

	caCertPath := filepath.Join(dir, "ca.crt")
	if _, err := os.Stat(caCertPath); err == nil {
		identity, err := node.LoadOrCreateIdentity(dir)
		if err == nil {
			fmt.Printf("already joined as %s (ca.crt exists in %s)\n", identity.NodeID, dir)
			return
		}
	}

	cfg := &config.Config{}
	cfg.Node.DataDir = dir
	if err := DoJoin(cfg, relayAddr, *token); err != nil {
		log.Fatalf("join failed: %v", err)
	}
	identity, _ := node.LoadOrCreateIdentity(dir)
	fmt.Printf("joined as %s\n", identity.NodeID)
}

func RunTag(args []string) {
	fs := flag.NewFlagSet("tag", flag.ExitOnError)
	sock := fs.String("socket", "", "control socket path")
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse tag <node-id> <tag>")
		os.Exit(1)
	}
	path := SocketPath([]string{"--socket", *sock})
	if _, err := CtrlDo(path, map[string]string{"cmd": "tag-add", "node_id": fs.Arg(0), "tag": fs.Arg(1)}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("tagged %s +%s\n", fs.Arg(0), fs.Arg(1))
}

func RunUntag(args []string) {
	fs := flag.NewFlagSet("untag", flag.ExitOnError)
	sock := fs.String("socket", "", "control socket path")
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse untag <node-id> <tag>")
		os.Exit(1)
	}
	path := SocketPath([]string{"--socket", *sock})
	if _, err := CtrlDo(path, map[string]string{"cmd": "tag-remove", "node_id": fs.Arg(0), "tag": fs.Arg(1)}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("untagged %s -%s\n", fs.Arg(0), fs.Arg(1))
}

func RunSetName(args []string) {
	fs := flag.NewFlagSet("name", flag.ExitOnError)
	sock := fs.String("socket", "", "control socket path")
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse name <node-id> <name>")
		os.Exit(1)
	}
	path := SocketPath([]string{"--socket", *sock})
	if _, err := CtrlDo(path, map[string]string{"cmd": "name-set", "node_id": fs.Arg(0), "name": fs.Arg(1)}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("named %s → %s\n", fs.Arg(0), fs.Arg(1))
}

func RunACL(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: pulse acl <list|add|remove>")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		sock := SocketPath(args[1:])
		resp, err := CtrlDo(sock, map[string]string{"cmd": "acl-list"})
		if err != nil {
			log.Fatal(err)
		}
		var rules []node.ACLRule
		_ = json.Unmarshal(resp["rules"], &rules)
		if len(rules) == 0 {
			fmt.Println("no ACL rules (open by default)")
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "#\tACTION\tFROM\tTO\tPORTS")
		for i, r := range rules {
			action := r.Action
			if action == "" {
				action = "allow"
			}
			src := r.SrcPattern
			if src == "" {
				src = "*"
			}
			_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n",
				i, action, src, r.DstPattern, node.FormatPortRanges(r.Ports))
		}
		_ = tw.Flush()

	case "add":
		fs := flag.NewFlagSet("acl add", flag.ExitOnError)
		sock := fs.String("socket", "", "control socket path")
		from := fs.String("from", "*", "source pattern")
		to := fs.String("to", "*", "destination pattern")
		ports := fs.String("ports", "", "port ranges (e.g. 22,80,443)")
		deny := fs.Bool("deny", false, "deny rule (default: allow)")
		_ = fs.Parse(args[1:])
		action := "allow"
		if *deny {
			action = "deny"
		}
		var portRanges []node.PortRange
		if *ports != "" {
			var err error
			portRanges, err = node.ParsePortRanges(*ports)
			if err != nil {
				log.Fatalf("bad --ports: %v", err)
			}
		}
		rule := node.ACLRule{Action: action, SrcPattern: *from, DstPattern: *to, Ports: portRanges}
		path := SocketPath([]string{"--socket", *sock})
		if _, err := CtrlDo(path, map[string]interface{}{"cmd": "acl-add", "acl_rule": rule}); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("acl: %s %s → %s ports=%s\n", action, *from, *to, node.FormatPortRanges(portRanges))

	case "remove":
		fs := flag.NewFlagSet("acl remove", flag.ExitOnError)
		sock := fs.String("socket", "", "control socket path")
		_ = fs.Parse(args[1:])
		if fs.NArg() < 1 {
			_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse acl remove <index>")
			os.Exit(1)
		}
		idx, err := strconv.Atoi(fs.Arg(0))
		if err != nil {
			log.Fatalf("bad index: %v", err)
		}
		path := SocketPath([]string{"--socket", *sock})
		if _, err := CtrlDo(path, map[string]interface{}{"cmd": "acl-remove", "index": idx}); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("acl: removed rule #%d\n", idx)

	default:
		fmt.Printf("unknown acl subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func RunRevoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	sock := fs.String("socket", "", "control socket path")
	nodeID := fs.String("node", "", "node ID to revoke (required)")
	_ = fs.Parse(args)
	if *nodeID == "" {
		log.Fatal("--node is required")
	}
	path := SocketPath([]string{"--socket", *sock})
	if _, err := CtrlDo(path, map[string]string{"cmd": "revoke", "node_id": *nodeID}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("node %s revoked\n", *nodeID)
}

func RunDNS(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: pulse dns <list|add|remove>")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		sock := SocketPath(args[1:])
		resp, err := CtrlDo(sock, map[string]string{"cmd": "dns-list"})
		if err != nil {
			log.Fatal(err)
		}
		var zones []node.DNSZone
		_ = json.Unmarshal(resp["zones"], &zones)
		if len(zones) == 0 {
			fmt.Println("no custom DNS records")
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "NAME\tTYPE\tVALUE\tTTL")
		for _, z := range zones {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", z.Name, z.Type, z.Value, z.TTL)
		}
		_ = tw.Flush()

	case "add":
		fs := flag.NewFlagSet("dns add", flag.ExitOnError)
		sock := fs.String("socket", "", "control socket path")
		recType := fs.String("type", "A", "record type (A, CNAME, TXT)")
		ttl := fs.Int("ttl", 300, "TTL in seconds")
		_ = fs.Parse(args[1:])
		if fs.NArg() < 2 {
			log.Fatal("usage: pulse dns add [--type A] <name> <value>")
		}
		path := SocketPath([]string{"--socket", *sock})
		zone := node.DNSZone{Name: fs.Arg(0), Type: *recType, Value: fs.Arg(1), TTL: uint32(*ttl)}
		if _, err := CtrlDo(path, map[string]interface{}{"cmd": "dns-add", "zone": zone}); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("added %s %s → %s\n", zone.Name, zone.Type, zone.Value)

	case "remove":
		fs := flag.NewFlagSet("dns remove", flag.ExitOnError)
		sock := fs.String("socket", "", "control socket path")
		recType := fs.String("type", "", "record type (optional)")
		_ = fs.Parse(args[1:])
		if fs.NArg() < 1 {
			log.Fatal("usage: pulse dns remove <name>")
		}
		path := SocketPath([]string{"--socket", *sock})
		if _, err := CtrlDo(path, map[string]string{"cmd": "dns-remove", "name": fs.Arg(0), "type": *recType}); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("removed %s\n", fs.Arg(0))

	default:
		fmt.Printf("unknown dns subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func RunRoute(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: pulse route <add|remove|list>")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		sock := SocketPath(args[1:])
		resp, err := CtrlDo(sock, map[string]string{"cmd": "route-list"})
		if err != nil {
			log.Fatal(err)
		}
		var routes []struct {
			CIDR   string `json:"cidr"`
			NodeID string `json:"node_id"`
		}
		_ = json.Unmarshal(resp["routes"], &routes)
		if len(routes) == 0 {
			fmt.Println("no exit routes configured")
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "CIDR\tEXIT NODE")
		for _, r := range routes {
			_, _ = fmt.Fprintf(tw, "%s\t%s\n", r.CIDR, r.NodeID)
		}
		_ = tw.Flush()

	case "add":
		fs := flag.NewFlagSet("route add", flag.ExitOnError)
		sock := fs.String("socket", "", "control socket path")
		_ = fs.Parse(args[1:])
		rest := fs.Args()
		if len(rest) != 3 || rest[1] != "via" {
			_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse route add <cidr> via <node-id>")
			os.Exit(1)
		}
		path := SocketPath([]string{"--socket", *sock})
		if _, err := CtrlDo(path, map[string]string{"cmd": "route-add", "cidr": rest[0], "via": rest[2]}); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("route added: %s via %s\n", rest[0], rest[2])

	case "remove":
		fs := flag.NewFlagSet("route remove", flag.ExitOnError)
		sock := fs.String("socket", "", "control socket path")
		_ = fs.Parse(args[1:])
		if fs.NArg() < 1 {
			_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse route remove <cidr>")
			os.Exit(1)
		}
		path := SocketPath([]string{"--socket", *sock})
		if _, err := CtrlDo(path, map[string]string{"cmd": "route-remove", "cidr": fs.Arg(0)}); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("route removed: %s\n", fs.Arg(0))

	default:
		fmt.Printf("unknown route subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func RunToken(args []string) {
	if len(args) == 0 {
		sock := SocketPath(args)
		resp, err := CtrlDo(sock, map[string]string{"cmd": "token"})
		if err != nil {
			log.Fatal(err)
		}
		var token string
		_ = json.Unmarshal(resp["token"], &token)
		fmt.Println(token)
		return
	}

	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("token create", flag.ExitOnError)
		sock := fs.String("socket", "", "control socket path")
		ttl := fs.String("ttl", "", "token TTL (e.g. 1h, 24h)")
		maxUses := fs.Int("max-uses", 0, "max uses (0=unlimited)")
		_ = fs.Parse(args[1:])
		path := SocketPath([]string{"--socket", *sock})
		resp, err := CtrlDo(path, map[string]interface{}{"cmd": "token-create", "ttl": *ttl, "max_uses": *maxUses})
		if err != nil {
			log.Fatal(err)
		}
		var t node.JoinToken
		_ = json.Unmarshal(resp["token"], &t)
		fmt.Println(t.Value)

	case "list":
		sock := SocketPath(args[1:])
		resp, err := CtrlDo(sock, map[string]string{"cmd": "token-list"})
		if err != nil {
			log.Fatal(err)
		}
		var tokens []node.JoinToken
		_ = json.Unmarshal(resp["tokens"], &tokens)
		if len(tokens) == 0 {
			fmt.Println("no tokens (using legacy --token)")
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "VALUE\tCREATED\tEXPIRES\tMAX\tUSED\tSTATUS")
		for _, t := range tokens {
			expires := "never"
			if !t.ExpiresAt.IsZero() {
				expires = t.ExpiresAt.Format(time.RFC3339)
			}
			maxStr := "unlimited"
			if t.MaxUses > 0 {
				maxStr = fmt.Sprint(t.MaxUses)
			}
			status := "valid"
			if t.IsExpired() {
				status = "expired"
			} else if t.IsExhausted() {
				status = "exhausted"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n",
				t.Value[:16]+"...", t.CreatedAt.Format(time.RFC3339), expires, maxStr, t.UseCount, status)
		}
		_ = tw.Flush()

	case "revoke":
		fs := flag.NewFlagSet("token revoke", flag.ExitOnError)
		sock := fs.String("socket", "", "control socket path")
		_ = fs.Parse(args[1:])
		if fs.NArg() < 1 {
			_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse token revoke <prefix>")
			os.Exit(1)
		}
		path := SocketPath([]string{"--socket", *sock})
		if _, err := CtrlDo(path, map[string]interface{}{"cmd": "token-revoke", "token_prefix": fs.Arg(0)}); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("token revoked (prefix=%s)\n", fs.Arg(0))

	default:
		fmt.Printf("unknown token subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func RunConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	pulseAddr := fs.String("pulse", "localhost:7000", "pulse TCP listener address")
	nodeID := fs.String("node", "", "destination node ID (required)")
	destAddr := fs.String("dest", "", "destination address on target node (required)")
	_ = fs.Parse(args)
	if *nodeID == "" || *destAddr == "" {
		_, _ = fmt.Fprintln(os.Stderr, "pulse connect: --node and --dest are required")
		os.Exit(1)
	}
	conn, err := client.Dial(*pulseAddr, *nodeID, *destAddr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "pulse connect: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				_, _ = conn.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				_, _ = os.Stdout.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
}

func RunForward(args []string) {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	pulseAddr := fs.String("pulse", "localhost:7000", "pulse TCP listener address")
	nodeID := fs.String("node", "", "destination node ID (required)")
	destAddr := fs.String("dest", "", "destination address on target node (required)")
	localAddr := fs.String("local", "", "local listen address, e.g. :3389 (required)")
	_ = fs.Parse(args)
	if *nodeID == "" || *destAddr == "" || *localAddr == "" {
		_, _ = fmt.Fprintln(os.Stderr, "pulse forward: --node, --dest and --local are required")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	fwd := client.NewForwarder(*pulseAddr, *nodeID, *destAddr)
	log.Printf("forwarding %s → node %s → %s", *localAddr, *nodeID, *destAddr)
	if err := fwd.ListenAndServe(ctx, *localAddr); err != nil {
		log.Fatalf("forward: %v", err)
	}
}

func RunCA(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: pulse ca <sign>")
		os.Exit(1)
	}
	switch args[0] {
	case "sign":
		RunCASign(args[1:])
	default:
		fmt.Printf("unknown ca subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func RunCASign(args []string) {
	fs := flag.NewFlagSet("ca sign", flag.ExitOnError)
	caDir := fs.String("ca-dir", "", "CA data directory (required)")
	identityKey := fs.String("identity", "", "path to node's identity.key (required)")
	outDir := fs.String("out", ".", "directory to write identity.crt and ca.crt")
	_ = fs.Parse(args)
	if *caDir == "" || *identityKey == "" {
		log.Fatal("--ca-dir and --identity are required")
	}
	ca, err := node.LoadCA(*caDir, "")
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}
	resp, nodeID, err := node.SignIdentityFromKeyFile(*identityKey, ca)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	if err := node.StoreJoinResult(*outDir, resp); err != nil {
		log.Fatalf("store: %v", err)
	}
	fmt.Printf("signed cert for node %s → %s/{identity.crt,ca.crt}\n", nodeID, *outDir)
}

func RunPin(args []string) {
	if len(args) < 2 {
		_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse pin <node-id> <via-relay-id>")
		os.Exit(1)
	}
	sock := SocketPath(args[2:])
	if _, err := CtrlDo(sock, map[string]string{"cmd": "pin", "node_id": args[0], "via": args[1]}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("pinned %s via %s\n", args[0], args[1])
}

func RunUnpin(args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse unpin <node-id>")
		os.Exit(1)
	}
	sock := SocketPath(args[1:])
	if _, err := CtrlDo(sock, map[string]string{"cmd": "unpin", "node_id": args[0]}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("unpinned %s\n", args[0])
}

func RunRestart(args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse restart <node-id>")
		os.Exit(1)
	}
	sock := SocketPath(args[1:])
	if _, err := CtrlDo(sock, map[string]string{"cmd": "remote-restart", "node_id": args[0]}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("restart signal sent to %s\n", args[0])
}

func RunRemoteConfig(args []string) {
	fs := flag.NewFlagSet("remote-config", flag.ExitOnError)
	sock := fs.String("socket", "", "control socket path")
	nodeID := fs.String("node", "", "target node ID")
	_ = fs.Parse(args)

	if *nodeID == "" || fs.NArg() == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse remote-config --node <id> key=value [key=value ...]")
		os.Exit(1)
	}

	cfg := make(map[string]string)
	for _, arg := range fs.Args() {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			log.Fatalf("invalid key=value pair: %s", arg)
		}
		cfg[parts[0]] = parts[1]
	}

	path := SocketPath([]string{"--socket", *sock})
	if _, err := CtrlDo(path, map[string]interface{}{
		"cmd":           "remote-config",
		"node_id":       *nodeID,
		"remote_config": cfg,
	}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("config pushed to %s: %v\n", *nodeID, cfg)
}

func RunGroups(args []string) {
	sock := SocketPath(args)
	resp, err := CtrlDo(sock, map[string]string{"cmd": "status"})
	if err != nil {
		log.Fatal(err)
	}
	// Build groups from peer tags.
	var peers []node.PeerEntry
	_ = json.Unmarshal(resp["peers"], &peers)
	groups := make(map[string]int)
	for _, p := range peers {
		for _, tag := range p.Tags {
			groups[tag]++
		}
	}
	if len(groups) == 0 {
		fmt.Println("no groups (no tagged nodes)")
		return
	}
	for tag, count := range groups {
		fmt.Printf("%-30s %d nodes\n", tag, count)
	}
}

func RunTemplate(args []string) {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse template <list|add|remove>")
		os.Exit(1)
	}
	sock := SocketPath(args[1:])
	switch args[0] {
	case "list":
		// Templates are on the scribe HTTP API — use curl or the TUI.
		fmt.Println("Templates are managed via the scribe HTTP API:")
		fmt.Println("  GET    /api/templates")
		fmt.Println("  POST   /api/templates {\"pattern\":\"tag:gw\", \"config\":{...}}")
		fmt.Println("  DELETE /api/templates {\"pattern\":\"tag:gw\"}")
	default:
		fmt.Printf("unknown template subcommand: %s\n", args[0])
		os.Exit(1)
	}
	_ = sock
}

func RunBulk(args []string) {
	if len(args) < 2 {
		_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse bulk <tag-pattern> <restart|push_config>")
		os.Exit(1)
	}
	sock := SocketPath(args[2:])
	// Bulk operations go through the scribe, so we need the node to be the scribe.
	cmd := map[string]interface{}{
		"cmd": "status", // just to verify connectivity
	}
	if _, err := CtrlDo(sock, cmd); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Bulk operations are managed via the scribe HTTP API:\n")
	fmt.Printf("  POST /api/bulk {\"pattern\":\"%s\", \"action\":\"%s\"}\n", args[0], args[1])
}

func RunTop(args []string) {
	sock := SocketPath(args)
	if err := tui.New(sock).Run(); err != nil {
		log.Fatalf("tui: %v", err)
	}
}

var pulseCommands = []string{
	"start", "stop", "status", "id", "cert", "top",
	"join", "invite", "tag", "untag", "name", "revoke",
	"acl", "token", "connect", "forward", "dns", "route",
	"events", "logs", "stats", "mesh-ip",
	"restart", "remote-config", "pin", "unpin", "groups", "template", "bulk",
	"ca", "completion", "version", "help",
}

func RunCompletion(args []string) {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "Usage: pulse completion <bash|zsh|fish>")
		os.Exit(1)
	}
	cmds := strings.Join(pulseCommands, " ")
	switch args[0] {
	case "bash":
		fmt.Printf(`_pulse() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "%s" -- "$cur") )
    fi
}
complete -F _pulse pulse
`, cmds)
	case "zsh":
		fmt.Printf(`#compdef pulse
_pulse() {
    local -a commands
    commands=(%s)
    _describe 'command' commands
}
compdef _pulse pulse
`, cmds)
	case "fish":
		for _, cmd := range pulseCommands {
			fmt.Printf("complete -c pulse -n '__fish_use_subcommand' -a '%s'\n", cmd)
		}
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unknown shell: %s (use bash, zsh, or fish)\n", args[0])
		os.Exit(1)
	}
}

func PrintUsage() {
	fmt.Print(`pulse — mesh relay daemon

Lifecycle:
  pulse [flags] [peers...]                start in foreground
  pulse start [flags] [peers...]          start as background daemon
  pulse stop                              stop the running daemon
  pulse id                                print this node's ID
  pulse cert                              show certificate expiry and status
  pulse top                               interactive TUI dashboard

Mesh:
  pulse join <relay-addr> --token <tok>   join a mesh (one-time)
  pulse join <pls_code>                   join using an invite code
  pulse invite [--network <id>]           generate an invite code
  pulse status                            show live mesh status
  pulse tag <node-id> <tag>               add a tag to a node
  pulse untag <node-id> <tag>             remove a tag from a node
  pulse name <node-id> <name>             set a friendly name for a node
  pulse revoke --node <id>                revoke a node

Policy:
  pulse acl list                          show ACL rules
  pulse acl add --from <pat> --to <pat>   add an ACL rule (--deny, --ports)
  pulse acl remove <index>                remove an ACL rule

Tokens:
  pulse token                             show master join token (CA only)
  pulse token create --ttl 1h             create a time-limited token
  pulse token create --max-uses 1         create a single-use token
  pulse token list                        list all tokens
  pulse token revoke <prefix>             revoke a token

Networking:
  pulse connect --node <id> --dest <addr> open tunnel (SSH ProxyCommand)
  pulse forward --node <id> ...           forward a local port through mesh
  pulse dns list|add|remove               manage DNS records
  pulse route list|add|remove             manage exit routes

Observability:
  pulse logs [-f] [-n 50]                 show daemon logs (tail/follow)
  pulse events [--type X] [--node X]      query structured event log
  pulse stats [node-id]                   show per-peer stats time series

Fleet:
  pulse restart <node-id>                 restart a remote node
  pulse remote-config --node <id> k=v     push config to a remote node
  pulse pin <node-id> <via-relay-id>      force traffic through a specific relay
  pulse unpin <node-id>                   remove route pin
  pulse groups                            show tag-based node groups
  pulse template list                     show config templates (scribe API)
  pulse bulk <pattern> <action>           bulk operation by tag pattern (scribe API)

Admin:
  pulse ca sign --ca-dir <dir> ...        sign a node cert offline
  pulse completion <bash|zsh|fish>        generate shell completions

Node flags:
  --data-dir <path>      persistent data directory (default ~/.pulse)
  --addr <addr>          advertised address (default :8443)
  --listen <addr>        bind address (default: same as --addr, use :443 behind NAT)
  --tcp <addr>           TCP tunnel listener (default :7000)
  --network <id>         network isolation ID (peers with different IDs are rejected)
  --join <addr>          CA relay address (auto-join on startup if not yet joined)
  --token <secret>       join token
  --log-level <level>    debug, info, warn, error (default: info)

Feature flags:
  --ca                   enable certificate authority
  --ca-token <secret>    join token the CA accepts (defaults to --token)
  --scribe               enable scribe (control plane + dashboard)
  --scribe-listen <addr> scribe HTTP API (default 127.0.0.1:8080)
  --socks                enable SOCKS5 proxy
  --socks-listen <addr>  SOCKS5 address (default 127.0.0.1:1080)
  --dns                  enable DNS server for .pulse
  --dns-listen <addr>    DNS address (default 127.0.0.1:5353)
  --tun                  enable TUN interface (Linux only)
  --tun-queues <N>       multi-queue TUN readers (default 1, higher for >1Gbps)
  --fec                  forward error correction on TUN pipes (lossy links)
  --exit                 enable exit node
  --exit-cidrs <cidrs>   comma-separated CIDRs this exit node advertises
  --mesh-cidr <cidr>     mesh IP range (default 10.100.0.0/16)
  --iouring              use io_uring for TUN I/O (Linux ≥5.1, auto-fallback)

Examples:
  # Home node (CA + scribe + all services):
  pulse --ca --scribe --socks --dns --tun --token mytoken

  # Relay node:
  pulse join relay.example.com:443 --token mytoken
  pulse start --addr relay.example.com:443 --tun

  # Client node:
  pulse join relay.example.com:443 --token mytoken
  pulse start --socks --dns --tun

  # Exit node:
  pulse start --exit --exit-cidrs 0.0.0.0/0 --tun relay.example.com:443
`)
}
