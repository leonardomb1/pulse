package node

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"io"
	"net"
	"sync"
)

// TunDevice is the interface for the optional layer-3 mesh VPN.
// Implemented by tunManager on Linux and tunStub elsewhere.
type TunDevice interface {
	Run(ctx context.Context)
	HandleInbound(conn net.Conn) // legacy one-shot stream (pre-pipe fallback)
	RunPipe(nodeID string, conn net.Conn)
	RefreshMeshIPs()
	UpdateMeshCIDR(newCIDR string) bool // reconfigure TUN IP+route when mesh CIDR changes; returns true if changed
}

// MeshIPFromNodeID derives a deterministic mesh IP from a node ID string
// within the configured mesh CIDR. The host part is derived from the first
// 4 hex chars of the nodeID (2 bytes), combined with the network prefix.
func MeshIPFromNodeID(nodeID string) net.IP {
	return MeshIPFromNodeIDWithCIDR(nodeID, "10.100.0.0/16")
}

// MeshIPFromNodeIDWithCIDR derives a mesh IP within the given CIDR.
// It uses FNV-1a hash of the full nodeID for good distribution and avoids
// both the network address (host 0) and broadcast address (max host).
func MeshIPFromNodeIDWithCIDR(nodeID, cidr string) net.IP {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return net.IP{10, 100, 0, 1}
	}

	if len(nodeID) < 4 {
		ip := make(net.IP, 4)
		copy(ip, ipNet.IP.To4())
		ip[3] = 1
		return ip
	}

	prefix := ipNet.IP.To4()
	mask := ipNet.Mask
	ones, bits := mask.Size()
	hostBits := bits - ones

	// maxHost is the number of usable host addresses (excluding network and broadcast).
	// For /24: 2^8 - 2 = 254, for /16: 2^16 - 2 = 65534.
	maxHost := (uint32(1) << hostBits) - 2
	if maxHost == 0 {
		// /31 or /32 — can't meaningfully assign
		ip := make(net.IP, 4)
		copy(ip, prefix)
		ip[3] = 1
		return ip
	}

	// FNV-1a hash of the full nodeID for good distribution.
	h := fnv.New32a()
	h.Write([]byte(nodeID))
	hash := h.Sum32()

	// hostNum in [1, maxHost] — avoids 0 (network) and maxHost+1 (broadcast).
	hostNum := (hash % maxHost) + 1

	// Convert prefix to uint32, add hostNum, convert back to IP.
	netAddr := binary.BigEndian.Uint32(prefix)
	ipVal := netAddr + hostNum

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipVal)
	return ip
}

// Packet pool: reuse 64KB buffers to avoid per-packet GC pressure.
var pktPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4+65535) // 4-byte header + max IP packet
		return &b
	},
}

func getPktBuf() *[]byte  { return pktPool.Get().(*[]byte) }
func putPktBuf(b *[]byte) { pktPool.Put(b) }

// tunFrameWrite writes a length-prefixed IP packet to w in a single write.
// Wire format: 4-byte little-endian length, then raw IP packet bytes.
func tunFrameWrite(w io.Writer, pkt []byte) error {
	buf := getPktBuf()
	defer putPktBuf(buf)
	b := (*buf)[:4+len(pkt)]
	binary.LittleEndian.PutUint32(b, uint32(len(pkt)))
	copy(b[4:], pkt)
	_, err := w.Write(b)
	return err
}

// tunFrameRead reads one length-prefixed IP packet from r into a pooled buffer.
// The caller must call putPktBuf when done with the returned buffer.
// Returns the buffer, the packet slice within it, and any error.
func tunFrameReadPooled(r io.Reader) (*[]byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n > 65535 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	buf := getPktBuf()
	pkt := (*buf)[:n]
	if _, err := io.ReadFull(r, pkt); err != nil {
		putPktBuf(buf)
		return nil, nil, err
	}
	return buf, pkt, nil
}

// ip4key extracts a 4-byte destination IP from an IPv4 packet header as a
// comparable value for map lookups — avoids net.IP.String() allocation.
type ip4key [4]byte

func dstIPKey(pkt []byte) ip4key {
	var k ip4key
	copy(k[:], pkt[16:20])
	return k
}

func tunLog(format string, args ...any) {
	Debugf("[tun] "+format, args...)
}
