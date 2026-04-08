//go:build linux

package node

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const tunRefreshInterval = 5 * time.Second

// tunPkt carries a packet through the per-peer write queue.
// buf is the pooled buffer that must be returned after writing.
type tunPkt struct {
	buf *[]byte
	pkt []byte
}

type tunManager struct {
	node     *Node
	devName  string
	meshCIDR string
	cidrMu   sync.Mutex // protects meshCIDR during reconfiguration
	fds      []*os.File // multi-queue TUN file descriptors

	// Atomic pointer swap — readers never lock.
	ipToID atomic.Pointer[map[ip4key]string]

	pipesMu sync.RWMutex
	pipes   map[string]net.Conn // nodeID → persistent bidirectional stream

	// Per-peer write queues: packets are routed to destination-specific channels.
	// Each peer has a dedicated writer goroutine that drains its channel and writes
	// to the pipe — no write contention between peers.
	peerQueuesMu sync.RWMutex
	peerQueues   map[string]chan tunPkt // nodeID → packet channel

	installedRoutesMu sync.Mutex
	installedRoutes   map[string]struct{}
}

func NewTunDevice(n *Node, devName, meshCIDR string) (TunDevice, error) {
	queues := n.cfg.Tun.Queues
	if queues <= 0 {
		queues = 1
	}
	multiQueue := queues > 1

	// Open the first queue (creates the device).
	fd0, err := openTunQueue(devName, multiQueue)
	if err != nil {
		return nil, fmt.Errorf("tun: open %s: %w", devName, err)
	}
	fds := []*os.File{fd0}

	// Open additional queues.
	for i := 1; i < queues; i++ {
		fd, err := openTunQueue(devName, multiQueue)
		if err != nil {
			for _, f := range fds {
				_ = f.Close()
			}
			return nil, fmt.Errorf("tun: open %s queue %d: %w", devName, i, err)
		}
		fds = append(fds, fd)
	}

	meshIP := MeshIPFromNodeIDWithCIDR(n.id, meshCIDR)
	if err := configureTun(devName, meshIP, meshCIDR); err != nil {
		for _, f := range fds {
			_ = f.Close()
		}
		return nil, fmt.Errorf("tun: configure %s: %w", devName, err)
	}

	// Advertise our mesh IP in the gossip table.
	if self, ok := n.table.Get(n.id); ok {
		self.MeshIP = meshIP.String()
		self.MetaVersion++
		n.table.UpsertForce(self)
	}

	// If this node is an exit node, enable IP forwarding and masquerade
	// so TUN packets from mesh clients get routed to the internet.
	if n.cfg.Exit.Enabled {
		configureExitForwarding(meshCIDR)
	}

	Infof("tun: interface %s up, mesh IP %s/%s (%d queues)", devName, meshIP, meshCIDR, queues)
	t := &tunManager{
		node:            n,
		devName:         devName,
		meshCIDR:        meshCIDR,
		fds:             fds,
		pipes:           make(map[string]net.Conn),
		peerQueues:      make(map[string]chan tunPkt),
		installedRoutes: make(map[string]struct{}),
	}
	emptyMap := make(map[ip4key]string)
	t.ipToID.Store(&emptyMap)
	return t, nil
}

func (t *tunManager) Run(ctx context.Context) {
	go t.refreshMeshIPs(ctx)

	// Select reader implementation: io_uring (batched syscalls) or standard fd.Read.
	// io_uring is only used when explicitly enabled and available on this kernel.
	useIOURing := t.node.cfg.Tun.IOURing && ioUringAvailable()
	if t.node.cfg.Tun.IOURing && !useIOURing {
		Warnf("tun: --iouring requested but io_uring not available on this kernel — using standard reader")
	}

	reader := t.tunReader
	if useIOURing {
		reader = t.tunReaderIOURing
		Infof("tun: using io_uring for TUN reads")
	}

	// WireGuard-inspired pipeline:
	//   N readers (one per TUN queue) → per-peer channel → per-peer writer → pipe
	//
	// Multi-queue TUN distributes packets across readers for linear scaling.
	// Per-peer channels avoid pipe write contention.
	// Per-peer writers batch-drain their channel for fewer syscalls.
	for i, fd := range t.fds {
		if i < len(t.fds)-1 {
			go reader(ctx, fd)
		} else {
			// Last reader runs on the calling goroutine (blocks).
			reader(ctx, fd)
		}
	}
}

func (t *tunManager) tunReader(ctx context.Context, fd *os.File) {
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			_ = fd.Close()
			return
		}
		n, err := fd.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				_ = fd.Close()
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
			_, _ = conn.Write(hdr)
			_ = tunFrameWrite(conn, pkt)
			_ = conn.Close()
			return
		}
	}

	// Copy packet into pooled buffer and send to the per-peer write queue.
	pbuf := getPktBuf()
	cp := (*pbuf)[:len(pkt)]
	copy(cp, pkt)

	q := t.getOrCreatePeerQueue(targetID, pipe)
	select {
	case q <- tunPkt{buf: pbuf, pkt: cp}:
	default:
		putPktBuf(pbuf) // queue full — return buffer, drop packet
	}
}

// getOrCreatePeerQueue returns (or creates) a per-peer write channel + writer goroutine.
func (t *tunManager) getOrCreatePeerQueue(nodeID string, pipe net.Conn) chan tunPkt {
	t.peerQueuesMu.RLock()
	q, ok := t.peerQueues[nodeID]
	t.peerQueuesMu.RUnlock()
	if ok {
		return q
	}

	t.peerQueuesMu.Lock()
	if q, ok := t.peerQueues[nodeID]; ok {
		t.peerQueuesMu.Unlock()
		return q
	}
	q = make(chan tunPkt, 1024)
	t.peerQueues[nodeID] = q
	t.peerQueuesMu.Unlock()

	go t.peerWriter(nodeID, pipe, q)
	return q
}

// peerWriter drains the per-peer queue and writes packets to the pipe.
// Batch-drains: after writing one packet, drains all immediately available
// packets before yielding — coalesces syscalls under load.
//
// When FEC is enabled, the encoder adapts its group size based on the measured
// per-peer loss rate from the prober. Every fecAdaptInterval packets, the
// writer checks the current loss rate and may switch to a different group size.
func (t *tunManager) peerWriter(nodeID string, pipe net.Conn, q chan tunPkt) {
	defer func() {
		t.peerQueuesMu.Lock()
		delete(t.peerQueues, nodeID)
		t.peerQueuesMu.Unlock()
	}()

	useFEC := t.node.cfg.Tun.FEC
	var enc *fecEncoder
	var pktCount int
	const fecAdaptInterval = 50

	adaptFEC := func() {
		if !useFEC {
			return
		}
		entry, ok := t.node.table.Get(nodeID)
		var lossRate float64
		if ok {
			lossRate = entry.LossRate
		}
		desired := FECGroupSizeForLoss(lossRate)
		// When --fec is explicitly enabled, never fully disable — use lightest tier.
		// The receiver expects FEC wire format; sending plain frames would break it.
		if desired == 0 && useFEC {
			desired = 20
		}
		if enc != nil && desired == enc.GroupSize() {
			return
		}
		if enc != nil && enc.Pending() {
			_ = enc.FlushParity(pipe)
		}
		if desired == 0 {
			enc = nil
		} else {
			enc = NewFECEncoder(desired)
		}
	}

	adaptFEC()

	writePacket := func(pkt []byte) error {
		pktCount++
		if pktCount%fecAdaptInterval == 0 {
			adaptFEC()
		}
		if enc == nil {
			return tunFrameWrite(pipe, pkt)
		}
		ready, err := enc.AddAndWrite(pipe, pkt)
		if err != nil {
			return err
		}
		if ready {
			return enc.FlushParity(pipe)
		}
		return nil
	}

	for tp := range q {
		err := writePacket(tp.pkt)
		putPktBuf(tp.buf)
		if err != nil {
			t.pipesMu.Lock()
			if t.pipes[nodeID] == pipe {
				delete(t.pipes, nodeID)
			}
			t.pipesMu.Unlock()
			_ = pipe.Close()
			return
		}

		// Batch drain: write all queued packets without blocking.
		drained := true
		for drained {
			select {
			case tp = <-q:
				err := writePacket(tp.pkt)
				putPktBuf(tp.buf)
				if err != nil {
					_ = pipe.Close()
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
	defer func() { _ = conn.Close() }()

	writeTUN := func(pkt []byte) error {
		_, err := t.fds[0].Write(pkt)
		return err
	}
	if t.node.cfg.Tun.IOURing {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if iouringWrite := t.tunPipeWriterIOURing(ctx, t.fds[0]); iouringWrite != nil {
			writeTUN = iouringWrite
		}
	}

	for {
		buf, pkt, err := tunFrameReadPooled(conn)
		if err != nil {
			return
		}
		werr := writeTUN(pkt)
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
		_ = old.Close() // replace stale pipe
	}
	t.pipes[nodeID] = conn
	t.pipesMu.Unlock()

	defer func() {
		t.pipesMu.Lock()
		if t.pipes[nodeID] == conn {
			delete(t.pipes, nodeID)
		}
		t.pipesMu.Unlock()
		_ = conn.Close()
	}()

	tunLog("pipe established with %s (fec=%v)", nodeID, t.node.cfg.Tun.FEC)

	// Set up TUN write function — io_uring or standard.
	writeTUN := func(pkt []byte) error {
		_, err := t.fds[0].Write(pkt)
		return err
	}
	if t.node.cfg.Tun.IOURing {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if iouringWrite := t.tunPipeWriterIOURing(ctx, t.fds[0]); iouringWrite != nil {
			writeTUN = iouringWrite
			tunLog("pipe %s: using io_uring for TUN writes", nodeID)
		}
	}

	useFEC := t.node.cfg.Tun.FEC
	var dec *fecDecoder
	if useFEC {
		dec = NewFECDecoder()
	}

	for {
		var pkt []byte
		var buf *[]byte

		if useFEC {
			ft, gid, idx, payload, err := FECFrameRead(conn)
			if err != nil {
				tunLog("pipe to %s closed: %v", nodeID, err)
				return
			}
			// Feed to decoder — may return a recovered packet.
			recovered := dec.Add(ft, gid, idx, payload)
			if ft == fecFrameParity {
				// Parity frame — only useful for recovery, not a data packet.
				if recovered != nil {
					pkt = recovered
				} else {
					continue
				}
			} else {
				pkt = payload
			}
			if recovered != nil && ft == fecFrameParity {
				// Already handled above.
			} else if recovered != nil {
				// A previous missing packet was recovered — write it too.
				_ = writeTUN(recovered)
			}
		} else {
			var err error
			buf, pkt, err = tunFrameReadPooled(conn)
			if err != nil {
				tunLog("pipe to %s closed: %v", nodeID, err)
				return
			}
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
					_ = tunFrameWrite(fwdPipe, pkt)
					if buf != nil {
						putPktBuf(buf)
					}
					continue
				}
			}
		}
		if err := writeTUN(pkt); err != nil {
			if buf != nil {
				putPktBuf(buf)
			}
			tunLog("write to tun from %s: %v", nodeID, err)
			return
		}
		if buf != nil {
			putPktBuf(buf)
		}
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

var _ TunDevice = (*tunManager)(nil)

// UpdateMeshCIDR reconfigures the TUN interface when the scribe pushes a new
// mesh CIDR via NetworkConfig. This updates the interface IP, netmask, gossip
// self-entry, and rebuilds the IP→nodeID map.
func (t *tunManager) UpdateMeshCIDR(newCIDR string) bool {
	t.cidrMu.Lock()
	defer t.cidrMu.Unlock()
	if newCIDR == t.meshCIDR {
		return false
	}
	oldCIDR := t.meshCIDR
	meshIP := MeshIPFromNodeIDWithCIDR(t.node.id, newCIDR)
	if err := configureTun(t.devName, meshIP, newCIDR); err != nil {
		Warnf("tun: reconfigure for CIDR %s failed: %v", newCIDR, err)
		return false
	}
	t.meshCIDR = newCIDR

	// Update self-entry in gossip table with new mesh IP.
	if self, ok := t.node.table.Get(t.node.id); ok {
		self.MeshIP = meshIP.String()
		self.MetaVersion++
		t.node.table.UpsertForce(self)
	}

	// If exit node, reconfigure forwarding for new CIDR.
	if t.node.cfg.Exit.Enabled {
		configureExitForwarding(newCIDR)
	}

	Infof("tun: reconfigured %s from %s to %s (mesh IP %s)", t.devName, oldCIDR, newCIDR, meshIP)

	// Rebuild IP map with IPs derived from the new CIDR.
	t.RefreshMeshIPs()
	return true
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

// openTunQueue opens one TUN queue. With multiQueue=true, multiple fds can
// be opened for the same device for parallel read/write.
func openTunQueue(name string, multiQueue bool) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:unix.IFNAMSIZ], name)
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if multiQueue {
		flags |= unix.IFF_MULTI_QUEUE
	}
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		_ = unix.Close(fd)
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
	defer func() { _ = unix.Close(fd) }()

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
