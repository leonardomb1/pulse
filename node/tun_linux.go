//go:build linux

package node

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const tunRefreshInterval = 5 * time.Second

type tunManager struct {
	node     *Node
	devName  string
	meshCIDR string
	fd       *os.File

	mu     sync.RWMutex
	ipToID map[ip4key]string // mesh IP (4 bytes) → nodeID

	pipesMu sync.RWMutex
	pipes   map[string]net.Conn // nodeID → persistent bidirectional stream

	installedRoutesMu sync.Mutex
	installedRoutes   map[string]struct{} // CIDRs with kernel routes installed
}

func NewTunDevice(n *Node, devName, meshCIDR string) (TunDevice, error) {
	fd, err := openTun(devName)
	if err != nil {
		return nil, fmt.Errorf("tun: open %s: %w", devName, err)
	}

	meshIP := MeshIPFromNodeID(n.id)
	if err := configureTun(devName, meshIP, meshCIDR); err != nil {
		fd.Close()
		return nil, fmt.Errorf("tun: configure %s: %w", devName, err)
	}

	// Advertise our mesh IP in the gossip table.
	if self, ok := n.table.Get(n.id); ok {
		self.MeshIP = meshIP.String()
		n.table.Upsert(self)
	}

	// If this node is an exit node, enable IP forwarding and masquerade
	// so TUN packets from mesh clients get routed to the internet.
	if n.cfg.Exit.Enabled {
		configureExitForwarding(meshCIDR)
	}

	Infof("tun: interface %s up, mesh IP %s/%s", devName, meshIP, meshCIDR)
	return &tunManager{
		node:            n,
		devName:         devName,
		meshCIDR:        meshCIDR,
		fd:              fd,
		ipToID:          make(map[ip4key]string),
		pipes:           make(map[string]net.Conn),
		installedRoutes: make(map[string]struct{}),
	}, nil
}

func (t *tunManager) Run(ctx context.Context) {
	go t.refreshMeshIPs(ctx)

	type tunPkt struct {
		buf *[]byte // pool buffer, must be returned
		pkt []byte  // slice within buf
	}

	// Bounded worker pool to avoid unbounded goroutine churn per packet.
	pktCh := make(chan tunPkt, 256)
	const workers = 32
	for i := 0; i < workers; i++ {
		go func() {
			for tp := range pktCh {
				t.routePacket(tp.pkt)
				putPktBuf(tp.buf)
			}
		}()
	}

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			close(pktCh)
			t.fd.Close()
			return
		default:
		}

		n, err := t.fd.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				close(pktCh)
				return
			}
			tunLog("read error: %v", err)
			continue
		}
		if n < 20 {
			continue
		}
		// Use pooled buffer to avoid per-packet allocation.
		pbuf := getPktBuf()
		pkt := (*pbuf)[:n]
		copy(pkt, buf[:n])
		pktCh <- tunPkt{buf: pbuf, pkt: pkt}
	}
}

// HandleInbound is called when a legacy "tun" stream arrives (non-pipe path).
// Kept for compatibility with peers that haven't established a pipe yet.
func (t *tunManager) HandleInbound(conn net.Conn) {
	defer conn.Close()
	for {
		buf, pkt, err := tunFrameReadPooled(conn)
		if err != nil {
			return
		}
		_, werr := t.fd.Write(pkt)
		putPktBuf(buf)
		if werr != nil {
			tunLog("write to tun: %v", werr)
			return
		}
	}
}

// RunPipe registers and runs a persistent bidirectional TUN pipe to a peer.
// Packets received on the pipe are written directly to the local TUN device.
// Call this both when initiating (lower nodeID) and when accepting a "tunpipe" stream.
func (t *tunManager) RunPipe(nodeID string, conn net.Conn) {
	t.pipesMu.Lock()
	if old, ok := t.pipes[nodeID]; ok {
		old.Close() // replace stale pipe
	}
	t.pipes[nodeID] = conn
	t.pipesMu.Unlock()

	defer func() {
		t.pipesMu.Lock()
		if t.pipes[nodeID] == conn {
			delete(t.pipes, nodeID)
		}
		t.pipesMu.Unlock()
		conn.Close()
	}()

	tunLog("pipe established with %s", nodeID)
	for {
		buf, pkt, err := tunFrameReadPooled(conn)
		if err != nil {
			tunLog("pipe to %s closed: %v", nodeID, err)
			return
		}
		// If the packet is destined for another mesh peer, forward it directly
		// through that peer's pipe instead of writing to TUN.
		if len(pkt) >= 20 && pkt[0]>>4 == 4 {
			key := dstIPKey(pkt)
			t.mu.RLock()
			fwdNodeID, ok := t.ipToID[key]
			t.mu.RUnlock()
			if ok && fwdNodeID != nodeID {
				t.pipesMu.RLock()
				fwdPipe := t.pipes[fwdNodeID]
				t.pipesMu.RUnlock()
				if fwdPipe != nil {
					tunFrameWrite(fwdPipe, pkt)
					putPktBuf(buf)
					continue
				}
			}
		}
		if _, err := t.fd.Write(pkt); err != nil {
			putPktBuf(buf)
			tunLog("write to tun from %s: %v", nodeID, err)
			return
		}
		putPktBuf(buf)
	}
}

// routePacket routes an outbound IPv4 packet through the mesh via the peer pipe.
func (t *tunManager) routePacket(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return
	}
	key := dstIPKey(pkt)

	t.mu.RLock()
	nodeID, ok := t.ipToID[key]
	t.mu.RUnlock()
	if !ok {
		// Not a mesh IP — check exit routes for external traffic.
		exitNodeID := t.node.exitRoutes.Lookup(net.IP(key[:]))
		if exitNodeID == "" {
			return
		}
		nodeID = exitNodeID
	}

	// Fast path: send through persistent pipe (zero stream-open overhead).
	t.pipesMu.RLock()
	pipe := t.pipes[nodeID]
	t.pipesMu.RUnlock()

	if pipe != nil {
		if err := tunFrameWrite(pipe, pkt); err != nil {
			tunLog("pipe write to %s: %v", nodeID, err)
			t.pipesMu.Lock()
			if t.pipes[nodeID] == pipe {
				delete(t.pipes, nodeID)
			}
			t.pipesMu.Unlock()
			pipe.Close()
		}
		return
	}

	// No direct pipe — find a relay that can forward the packet.
	// The router knows the best next-hop for the destination node; if that
	// next-hop has a pipe, send the packet there for forwarding.
	session, err := t.node.router.Resolve(nodeID)
	if err != nil {
		return
	}
	// Identify which peer owns this session and use their pipe.
	relayID := t.node.registry.SessionOwner(session)
	if relayID != "" {
		t.pipesMu.RLock()
		relayPipe := t.pipes[relayID]
		t.pipesMu.RUnlock()
		if relayPipe != nil {
			tunFrameWrite(relayPipe, pkt)
			return
		}
	}

	// Last resort: open a one-shot stream (happens only before any pipe is ready).
	conn, err := session.Open()
	if err != nil {
		return
	}
	defer conn.Close()

	hdr, _ := marshalStreamMsg(streamMsg{Type: "tun", NodeID: t.node.id})
	if _, err := conn.Write(hdr); err != nil {
		return
	}
	tunFrameWrite(conn, pkt)
}

// RefreshMeshIPs immediately rebuilds the IP→nodeID map from the gossip table
// and syncs auto-learned exit routes.
func (t *tunManager) RefreshMeshIPs() {
	entries := t.node.table.Snapshot()
	m := make(map[ip4key]string, len(entries))
	for _, e := range entries {
		if e.MeshIP != "" && e.NodeID != t.node.id {
			ip := net.ParseIP(e.MeshIP).To4()
			if ip != nil {
				var k ip4key
				copy(k[:], ip)
				m[k] = e.NodeID
			}
		}
	}
	t.mu.Lock()
	t.ipToID = m
	t.mu.Unlock()

	// Sync exit routes from gossip and install kernel routes.
	t.node.exitRoutes.SyncFromGossip(t.node.table.ExitNodes())
	t.syncKernelRoutes()
}

// syncKernelRoutes installs/removes kernel routes for exit CIDRs via the TUN device.
func (t *tunManager) syncKernelRoutes() {
	routes := t.node.exitRoutes.Snapshot()
	wanted := make(map[string]struct{}, len(routes))
	for _, r := range routes {
		wanted[r.CIDR] = struct{}{}
	}

	t.installedRoutesMu.Lock()
	defer t.installedRoutesMu.Unlock()

	// Resolve interface index once.
	iface, err := net.InterfaceByName(t.devName)
	if err != nil {
		return
	}

	// Install new routes via netlink RTM_NEWROUTE.
	for cidr := range wanted {
		if _, ok := t.installedRoutes[cidr]; ok {
			continue
		}
		if err := netlinkRouteAdd(cidr, iface.Index); err != nil {
			tunLog("route add %s dev %s: %v", cidr, t.devName, err)
			continue
		}
		t.installedRoutes[cidr] = struct{}{}
		tunLog("route installed: %s dev %s", cidr, t.devName)
	}

	// Remove stale routes.
	for cidr := range t.installedRoutes {
		if _, ok := wanted[cidr]; ok {
			continue
		}
		netlinkRouteDel(cidr, iface.Index)
		delete(t.installedRoutes, cidr)
		tunLog("route removed: %s dev %s", cidr, t.devName)
	}
}

// netlinkRouteAdd adds a route via raw netlink (no exec needed, works with CAP_NET_ADMIN).
func netlinkRouteAdd(cidr string, ifIndex int) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ones, _ := ipNet.Mask.Size()
	dst := ip.To4()
	if dst == nil {
		return fmt.Errorf("IPv4 only")
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})

	// Build RTM_NEWROUTE message.
	msg := make([]byte, 0, 128)
	// nlmsghdr (16 bytes)
	msg = append(msg, 0, 0, 0, 0) // len (fill later)
	msg = appendU16(msg, unix.RTM_NEWROUTE)
	msg = appendU16(msg, unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_REPLACE|unix.NLM_F_ACK)
	msg = appendU32(msg, 1) // seq
	msg = appendU32(msg, 0) // pid
	// rtmsg (12 bytes)
	msg = append(msg, unix.AF_INET) // family
	msg = append(msg, byte(ones))   // dst_len
	msg = append(msg, 0)            // src_len
	msg = append(msg, 0)            // tos
	msg = append(msg, unix.RT_TABLE_MAIN)
	msg = append(msg, unix.RTPROT_STATIC)
	msg = append(msg, unix.RT_SCOPE_LINK)
	msg = append(msg, unix.RTN_UNICAST)
	msg = appendU32(msg, 0) // flags
	// RTA_DST
	msg = appendRTA(msg, unix.RTA_DST, dst[:4])
	// RTA_OIF
	oif := make([]byte, 4)
	binary.LittleEndian.PutUint32(oif, uint32(ifIndex))
	msg = appendRTA(msg, unix.RTA_OIF, oif)
	// Fill length.
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))

	return unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

func netlinkRouteDel(cidr string, ifIndex int) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	ones, _ := ipNet.Mask.Size()
	dst := ip.To4()
	if dst == nil {
		return
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})

	msg := make([]byte, 0, 128)
	msg = append(msg, 0, 0, 0, 0)
	msg = appendU16(msg, unix.RTM_DELROUTE)
	msg = appendU16(msg, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	msg = appendU32(msg, 1)
	msg = appendU32(msg, 0)
	msg = append(msg, unix.AF_INET)
	msg = append(msg, byte(ones))
	msg = append(msg, 0)
	msg = append(msg, 0)
	msg = append(msg, unix.RT_TABLE_MAIN)
	msg = append(msg, unix.RTPROT_STATIC)
	msg = append(msg, unix.RT_SCOPE_LINK)
	msg = append(msg, unix.RTN_UNICAST)
	msg = appendU32(msg, 0)
	msg = appendRTA(msg, unix.RTA_DST, dst[:4])
	oif := make([]byte, 4)
	binary.LittleEndian.PutUint32(oif, uint32(ifIndex))
	msg = appendRTA(msg, unix.RTA_OIF, oif)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))

	unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendRTA(b []byte, typ uint16, data []byte) []byte {
	rlen := 4 + len(data)
	aligned := (rlen + 3) &^ 3
	b = appendU16(b, uint16(rlen))
	b = appendU16(b, typ)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	_ = aligned
	return b
}

// refreshMeshIPs runs a background ticker to keep the IP map fresh.
func (t *tunManager) refreshMeshIPs(ctx context.Context) {
	ticker := time.NewTicker(tunRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.RefreshMeshIPs()
		}
	}
}

func openTun(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:unix.IFNAMSIZ], name)
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		unix.Close(fd)
		return nil, errno
	}

	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}

func configureTun(ifName string, meshIP net.IP, cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	// Use netlink ioctls directly so CAP_NET_ADMIN on the binary is sufficient
	// (shelling out to `ip` doesn't inherit the capability).
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)

	// Set IP address via SIOCSIFADDR.
	var ifr [40]byte
	copy(ifr[:unix.IFNAMSIZ], ifName)
	// sockaddr_in: family(2) + port(2) + addr(4)
	ifr[unix.IFNAMSIZ] = unix.AF_INET
	ifr[unix.IFNAMSIZ+1] = 0
	copy(ifr[unix.IFNAMSIZ+4:unix.IFNAMSIZ+8], meshIP.To4())
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCSIFADDR), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return fmt.Errorf("SIOCSIFADDR: %v", errno)
	}

	// Set netmask via SIOCSIFNETMASK.
	var maskIfr [40]byte
	copy(maskIfr[:unix.IFNAMSIZ], ifName)
	maskIfr[unix.IFNAMSIZ] = unix.AF_INET
	maskIfr[unix.IFNAMSIZ+1] = 0
	mask := ipNet.Mask
	copy(maskIfr[unix.IFNAMSIZ+4:unix.IFNAMSIZ+8], mask)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCSIFNETMASK), uintptr(unsafe.Pointer(&maskIfr[0]))); errno != 0 {
		return fmt.Errorf("SIOCSIFNETMASK: %v", errno)
	}

	// Bring interface up via SIOCSIFFLAGS.
	var flagIfr [40]byte
	copy(flagIfr[:unix.IFNAMSIZ], ifName)
	// Get current flags first.
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&flagIfr[0]))); errno != 0 {
		return fmt.Errorf("SIOCGIFFLAGS: %v", errno)
	}
	flags := *(*uint16)(unsafe.Pointer(&flagIfr[unix.IFNAMSIZ]))
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	*(*uint16)(unsafe.Pointer(&flagIfr[unix.IFNAMSIZ])) = flags
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&flagIfr[0]))); errno != 0 {
		return fmt.Errorf("SIOCSIFFLAGS: %v", errno)
	}

	return nil
}

// configureExitForwarding enables IP forwarding and NAT masquerade for exit node traffic.
func configureExitForwarding(meshCIDR string) {
	// Enable IP forwarding.
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		Warnf("tun: exit: enable ip_forward: %v (try running with sudo)", err)
	} else {
		Infof("tun: exit: ip_forward enabled")
	}

	// Detect the default external interface.
	extIface := defaultInterface()
	if extIface == "" {
		Warnf("tun: exit: could not detect default interface — masquerade not configured")
		return
	}

	// Add masquerade rule (idempotent with -C check).
	args := []string{"-t", "nat", "-A", "POSTROUTING", "-s", meshCIDR, "-o", extIface, "-j", "MASQUERADE"}
	checkArgs := []string{"-t", "nat", "-C", "POSTROUTING", "-s", meshCIDR, "-o", extIface, "-j", "MASQUERADE"}
	if exec.Command("iptables", checkArgs...).Run() == nil {
		Infof("tun: exit: masquerade rule already exists for %s via %s", meshCIDR, extIface)
		return
	}
	if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
		Warnf("tun: exit: iptables masquerade: %s: %v (try running with sudo)", out, err)
	} else {
		Infof("tun: exit: masquerade enabled: %s → %s", meshCIDR, extIface)
	}
}

// defaultInterface returns the name of the interface used for the default route.
func defaultInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	// Parse: "default via 10.0.0.1 dev eth0 ..."
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

var _ TunDevice = (*tunManager)(nil)
var _ = binary.LittleEndian
