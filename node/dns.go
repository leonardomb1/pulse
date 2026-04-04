package node

// DNS server for the .pulse TLD.
//
// Resolution strategy:
//   <nodeID>.pulse          → A 127.0.0.1  (SOCKS5 does actual routing)
//   <service>.<nodeID>.pulse→ A 127.0.0.1 + SRV pointing at the service port
//
// The A record always returns 127.0.0.1 because actual connection routing
// is handled by the SOCKS5 proxy, which understands .pulse hostnames.
// Applications that do DNS-then-connect (most HTTP clients, SSH) will hit
// the SOCKS5 proxy which intercepts on the domain name, not the IP.
//
// Usage — point system resolver at 127.0.0.1:5353 (or use in app configs):
//   ssh -o ProxyCommand="nc -x localhost:1080 %h %p" user@a3f2c1d4.pulse

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const pulseTLD = ".pulse."

// DNSServer resolves .pulse hostnames for the local mesh.
type DNSServer struct {
	listenAddr string
	table      *Table
	extraZones func() []DNSZone // callback returning scribe-distributed DNS zones
}

func NewDNSServer(addr string, table *Table, extraZones func() []DNSZone) *DNSServer {
	return &DNSServer{listenAddr: addr, table: table, extraZones: extraZones}
}

func (d *DNSServer) ListenAndServe(ctx context.Context) error {
	mux := dns.NewServeMux()
	mux.HandleFunc("pulse.", d.ServeDNS)
	mux.HandleFunc(".", d.serveExtraZones) // scribe-distributed zones for all other names

	udp := &dns.Server{Addr: d.listenAddr, Net: "udp", Handler: mux}
	tcp := &dns.Server{Addr: d.listenAddr, Net: "tcp", Handler: mux}

	errc := make(chan error, 2)
	go func() { errc <- udp.ListenAndServe() }()
	go func() { errc <- tcp.ListenAndServe() }()

	Infof("DNS server on %s (serving .pulse)", d.listenAddr)

	select {
	case <-ctx.Done():
		udp.ShutdownContext(ctx)
		tcp.ShutdownContext(ctx)
		return nil
	case err := <-errc:
		return err
	}
}

// ServeDNS handles all queries for *.pulse.
func (d *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	name := strings.ToLower(q.Name)

	nodeID, service := d.parseName(name)

	// Verify the node exists in the routing table.
	// If not (e.g. friendly alias like "db.pulse"), fall through to extraZones
	// which handles scribe-distributed CNAME/A/TXT records within .pulse.
	entry, knownNode := d.table.Get(nodeID)
	if nodeID == "" || !knownNode {
		d.serveExtraZones(w, r)
		return
	}

	// When TUN is enabled, nodes advertise a MeshIP in the gossip table.
	// Return that IP so the OS routes traffic through the pulse0 interface.
	// Fall back to 127.0.0.1 (SOCKS mode) when no mesh IP is set.
	nodeIP := d.resolveNodeIP(entry)

	switch q.Qtype {
	case dns.TypeA:
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   nodeIP,
		})

	case dns.TypeAAAA:
		// Return NOERROR with empty answer — IPv4-only for simplicity.

	case dns.TypeSRV:
		if service == "" {
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			return
		}
		for _, svc := range entry.Services {
			if strings.EqualFold(svc.Name, service) {
				m.Answer = append(m.Answer, &dns.SRV{
					Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 60},
					Priority: svc.Priority,
					Weight:   0,
					Port:     svc.Port,
					Target:   nodeID + ".pulse.",
				})
				// Add A record in additional section.
				m.Extra = append(m.Extra, &dns.A{
					Hdr: dns.RR_Header{
						Name: nodeID + ".pulse.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60,
					},
					A: nodeIP,
				})
			}
		}
		if len(m.Answer) == 0 {
			m.SetRcode(r, dns.RcodeNameError)
		}

	case dns.TypePTR:
		// Reverse DNS for 127.x.x.x — not supported.
		m.SetRcode(r, dns.RcodeRefused)

	default:
		// NOERROR, empty answer for unknown types.
	}

	w.WriteMsg(m)
}

// serveExtraZones handles DNS zones distributed by the scribe (non-.pulse names).
func (d *DNSServer) serveExtraZones(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 || d.extraZones == nil {
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	for _, zone := range d.extraZones() {
		zoneName := strings.ToLower(strings.TrimSuffix(zone.Name, "."))
		if zoneName != name {
			continue
		}
		ttl := zone.TTL
		if ttl == 0 {
			ttl = 60
		}
		switch zone.Type {
		case "A":
			if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   net.ParseIP(zone.Value),
				})
			}
		case "TXT":
			if q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY {
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
					Txt: []string{zone.Value},
				})
			}
		case "CNAME":
			target := dns.Fqdn(zone.Value)
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: target,
			})
			// Follow the CNAME: if target is a .pulse node, synthesize its A record.
			if strings.HasSuffix(strings.TrimSuffix(zone.Value, "."), ".pulse") {
				targetNodeID, _ := d.parseName(strings.ToLower(dns.Fqdn(zone.Value)))
				if entry, ok := d.table.Get(targetNodeID); ok {
					targetIP := d.nodeAddr(entry)
					if targetIP != nil {
						m.Answer = append(m.Answer, &dns.A{
							Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
							A:   targetIP,
						})
					}
				}
			}
		}
	}

	if len(m.Answer) == 0 {
		m.SetRcode(r, dns.RcodeNameError)
	}
	w.WriteMsg(m)
}

// nodeAddr extracts the IP address from a gossip PeerEntry's Addr field.
func (d *DNSServer) nodeAddr(entry PeerEntry) net.IP {
	host, _, err := net.SplitHostPort(entry.Addr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// resolveNodeIP returns the IP address to advertise for a node in DNS.
// When TUN is active the node advertises a MeshIP (10.100.x.x) which routes
// traffic through the pulse0 interface without SOCKS. Otherwise 127.0.0.1 is
// returned so the SOCKS proxy intercepts connections by hostname.
func (d *DNSServer) resolveNodeIP(entry PeerEntry) net.IP {
	if entry.MeshIP != "" {
		if ip := net.ParseIP(entry.MeshIP); ip != nil {
			return ip.To4()
		}
	}
	return net.ParseIP("127.0.0.1")
}

// parseName decomposes a .pulse FQDN into (nodeID, service).
//   "a3f2c1d4.pulse."          → ("a3f2c1d4", "")
//   "postgres.a3f2c1d4.pulse." → ("a3f2c1d4", "postgres")
func (d *DNSServer) parseName(name string) (nodeID, service string) {
	if !strings.HasSuffix(name, pulseTLD) {
		return "", ""
	}
	inner := strings.TrimSuffix(name, pulseTLD)
	inner = strings.TrimSuffix(inner, "_tcp.")
	inner = strings.TrimSuffix(inner, "_udp.")
	parts := strings.Split(strings.Trim(inner, "."), ".")
	if len(parts) == 0 || parts[0] == "" {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	// Last segment is nodeID, preceding segments form the service name.
	return parts[len(parts)-1], strings.Join(parts[:len(parts)-1], ".")
}

// ServiceRecord is a service advertised by a node in the gossip table.
type ServiceRecord struct {
	Name     string `json:"name"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority,omitempty"`
}

// RegisterService adds a service to the node's self-entry in the gossip table.
// Other nodes learn about it on the next gossip push.
func RegisterService(table *Table, selfID, addr string, pubKey []byte, isCA bool, svc ServiceRecord) {
	self, ok := table.Get(selfID)
	if !ok {
		return
	}
	for _, s := range self.Services {
		if s.Name == svc.Name {
			return // already registered
		}
	}
	self.Services = append(self.Services, svc)
	self.LastSeen = time.Now()
	table.Upsert(self)
}
