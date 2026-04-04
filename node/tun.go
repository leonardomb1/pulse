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

// MeshIPFromNodeID derives a deterministic mesh IP from a node ID string.
// nodeID is a 16-char hex string; we use the first 4 hex chars (2 bytes).
// Result is in the range 10.100.0.0–10.100.255.255.
func MeshIPFromNodeID(nodeID string) net.IP {
	if len(nodeID) < 4 {
		return net.IP{10, 100, 0, 1}
	}
	b, err := hex.DecodeString(nodeID[:4])
	if err != nil || len(b) < 2 {
		return net.IP{10, 100, 0, 1}
	}
	return net.IP{10, 100, b[0], b[1]}
}

// Packet pool: reuse 64KB buffers to avoid per-packet GC pressure.
var pktPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4+65535) // 4-byte header + max IP packet
		return &b
	},
}

func getPktBuf() *[]byte { return pktPool.Get().(*[]byte) }
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
