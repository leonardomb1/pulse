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
	"sync/atomic"
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

	// Atomic pointer swap — readers never lock.
	ipToID atomic.Pointer[map[ip4key]string]

	pipesMu sync.RWMutex
	pipes   map[string]net.Conn // nodeID → persistent bidirectional stream

	// Per-peer write queues: packets are routed to destination-specific channels.
	// Each peer has a dedicated writer goroutine that drains its channel and writes
	// to the pipe — no write contention between peers.
	peerQueuesMu sync.RWMutex
	peerQueues   map[string]chan []byte // nodeID → packet channel

	installedRoutesMu sync.Mutex
	installedRoutes   map[string]struct{}
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
	t := &tunManager{
		node:            n,
		devName:         devName,
		meshCIDR:        meshCIDR,
		fd:              fd,
		pipes:           make(map[string]net.Conn),
		peerQueues:      make(map[string]chan []byte),
		installedRoutes: make(map[string]struct{}),
	}
	emptyMap := make(map[ip4key]string)
	t.ipToID.Store(&emptyMap)
	return t, nil
}

func (t *tunManager) Run(ctx context.Context) {
	go t.refreshMeshIPs(ctx)

	// WireGuard-inspired pipeline:
	//   single reader → per-peer channel → per-peer writer → pipe
	//
	// Single reader avoids TUN fd contention.
	// Per-peer channels avoid pipe write contention.
	// Per-peer writers batch-drain their channel for fewer syscalls.
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			t.fd.Close()
			return
		}
		n, err := t.fd.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				t.fd.Close()
				return
			}
			continue
		}
		if n < 20 || buf[0]>>4 != 4 {
			continue
		}
		t.routeOutbound(buf[:n])
	}
}

// routeOutbound routes a packet to the appropriate per-peer write queue.
func (t *tunManager) routeOutbound(pkt []byte) {
	key := dstIPKey(pkt)

	m := *t.ipToID.Load()
	nodeID, ok := m[key]
	if !ok {
		exitNodeID := t.node.exitRoutes.Lookup(net.IP(key[:]))
		if exitNodeID == "" {
			return
		}
		nodeID = exitNodeID
	}

	// Resolve the actual pipe target (direct peer or relay).
	targetID := nodeID
	t.pipesMu.RLock()
	pipe := t.pipes[nodeID]
	t.pipesMu.RUnlock()

	if pipe == nil {
		// Try relay path.
		session, err := t.node.router.Resolve(nodeID)
		if err != nil {
			return
		}
		relayID := t.node.registry.SessionOwner(session)
		if relayID != "" {
			t.pipesMu.RLock()
			pipe = t.pipes[relayID]
			t.pipesMu.RUnlock()
			targetID = relayID
		}
		if pipe == nil {
			// Last resort: one-shot stream (before any pipe is ready).
			conn, err := session.Open()
			if err != nil {
				return
			}
			hdr, _ := marshalStreamMsg(streamMsg{Type: "tun", NodeID: t.node.id})
			conn.Write(hdr)
			tunFrameWrite(conn, pkt)
			conn.Close()
			return
		}
	}

	// Copy packet and send to the per-peer write queue.
	cp := make([]byte, len(pkt))
	copy(cp, pkt)

	q := t.getOrCreatePeerQueue(targetID, pipe)
	select {
	case q <- cp:
	default:
		// Queue full — drop packet (back-pressure, better than blocking the reader).
	}
}

// getOrCreatePeerQueue returns (or creates) a per-peer write channel + writer goroutine.
func (t *tunManager) getOrCreatePeerQueue(nodeID string, pipe net.Conn) chan []byte {
	t.peerQueuesMu.RLock()
	q, ok := t.peerQueues[nodeID]
	t.peerQueuesMu.RUnlock()
	if ok {
		return q
	}

	t.peerQueuesMu.Lock()
	// Double-check after acquiring write lock.
	if q, ok := t.peerQueues[nodeID]; ok {
		t.peerQueuesMu.Unlock()
		return q
	}
	q = make(chan []byte, 1024)
	t.peerQueues[nodeID] = q
	t.peerQueuesMu.Unlock()

	// Start dedicated writer goroutine for this peer.
	go t.peerWriter(nodeID, pipe, q)
	return q
}

// peerWriter drains the per-peer queue and writes packets to the pipe.
// Batch-drains: after writing one packet, drains all immediately available
// packets before yielding — coalesces syscalls under load.
func (t *tunManager) peerWriter(nodeID string, pipe net.Conn, q chan []byte) {
	defer func() {
		t.peerQueuesMu.Lock()
		delete(t.peerQueues, nodeID)
		t.peerQueuesMu.Unlock()
	}()

	for pkt := range q {
		if err := tunFrameWrite(pipe, pkt); err != nil {
			t.pipesMu.Lock()
			if t.pipes[nodeID] == pipe {
				delete(t.pipes, nodeID)
			}
			t.pipesMu.Unlock()
			pipe.Close()
			return
		}

		// Batch drain: write all queued packets without blocking.
		drained := true
		for drained {
			select {
			case pkt = <-q:
				if err := tunFrameWrite(pipe, pkt); err != nil {
					pipe.Close()
					return
				}
			default:
				drained = false
			}
		}
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
			m := *t.ipToID.Load()
			fwdNodeID, ok := m[key]
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
	// Atomic swap — readers never lock.
	t.ipToID.Store(&m)

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
