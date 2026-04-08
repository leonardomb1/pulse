package node

import (
	"context"
	"encoding/binary"
	"encoding/hex"
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
}

// MeshIPFromNodeID derives a deterministic mesh IP from a node ID string
// within the configured mesh CIDR. The host part is derived from the first
// 4 hex chars of the nodeID (2 bytes), combined with the network prefix.
func MeshIPFromNodeID(nodeID string) net.IP {
	return MeshIPFromNodeIDWithCIDR(nodeID, "10.100.0.0/16")
}

// MeshIPFromNodeIDWithCIDR derives a mesh IP within the given CIDR.
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
	b, err := hex.DecodeString(nodeID[:4])
	if err != nil || len(b) < 2 {
		ip := make(net.IP, 4)
		copy(ip, ipNet.IP.To4())
		ip[3] = 1
		return ip
	}

	prefix := ipNet.IP.To4()
	mask := ipNet.Mask
	ones, _ := mask.Size()

	// Build host bits from nodeID hash, apply to network prefix.
	ip := make(net.IP, 4)
	copy(ip, prefix)

	// For /16: bytes 2-3 are host. For /24: byte 3 is host. For /8: bytes 1-3.
	switch {
	case ones <= 8:
		ip[1] = b[0]
		ip[2] = b[1]
		ip[3] = b[0] ^ b[1]
	case ones <= 16:
		ip[2] = b[0]
		ip[3] = b[1]
	case ones <= 24:
		ip[3] = b[0]
	}

	// Avoid network address (all zeros host) and broadcast (all ones host).
	if ip.Equal(ipNet.IP) {
		ip[3] |= 1
	}

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
