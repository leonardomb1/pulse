package node

// XOR-based forward error correction for TUN pipes.
//
// For every fecGroupSize data packets, one parity packet is generated.
// The parity is the XOR of all data packets in the group. If any single
// packet in the group is lost, the receiver can reconstruct it by XORing
// the remaining packets with the parity.
//
// Wire format for FEC-enabled pipes:
//   byte 0:    frame type (0=data, 1=parity)
//   byte 1-2:  group ID (uint16, wraps around)
//   byte 3:    index within group (0..fecGroupSize-1 for data, 255 for parity)
//   byte 4-7:  payload length (uint32 little-endian)
//   byte 8+:   payload
//
// This adds 8 bytes of overhead per packet (vs 4 bytes without FEC).

import (
	"encoding/binary"
	"io"
)

const (
	fecGroupSize   = 10 // data packets per FEC group
	fecFrameData   = 0
	fecFrameParity = 1
	fecHeaderSize  = 8 // type(1) + groupID(2) + index(1) + length(4)
)

// fecEncoder generates parity packets for outbound TUN traffic.
type fecEncoder struct {
	groupID uint16
	idx     int
	parity  []byte
	maxLen  int // longest packet in this group (parity must be this long)
}

func NewFECEncoder() *fecEncoder {
	return &fecEncoder{parity: make([]byte, 65535)}
}

// AddAndWrite writes a data packet with FEC header to w.
// Returns true if a parity packet should be flushed (group complete).
func (e *fecEncoder) AddAndWrite(w io.Writer, pkt []byte) (parityReady bool, err error) {
	// Write data frame.
	if err := fecFrameWrite(w, fecFrameData, e.groupID, byte(e.idx), pkt); err != nil {
		return false, err
	}

	// XOR into running parity.
	if len(pkt) > e.maxLen {
		e.maxLen = len(pkt)
	}
	xorInto(e.parity[:e.maxLen], pkt)

	e.idx++
	if e.idx >= fecGroupSize {
		parityReady = true
	}
	return
}

// FlushParity writes the parity packet and resets for the next group.
func (e *fecEncoder) FlushParity(w io.Writer) error {
	err := fecFrameWrite(w, fecFrameParity, e.groupID, 255, e.parity[:e.maxLen])
	e.groupID++
	e.idx = 0
	e.maxLen = 0
	for i := range e.parity {
		e.parity[i] = 0
	}
	return err
}

// fecDecoder reconstructs lost packets from parity.
type fecDecoder struct {
	groups map[uint16]*fecGroup
}

type fecGroup struct {
	packets  [fecGroupSize][]byte // nil = not yet received
	parity   []byte
	received int
	maxLen   int
}

func NewFECDecoder() *fecDecoder {
	return &fecDecoder{groups: make(map[uint16]*fecGroup)}
}

// Add processes a received FEC frame. Returns a reconstructed packet if one
// was recovered, or nil if no recovery needed/possible.
func (d *fecDecoder) Add(frameType byte, groupID uint16, index byte, payload []byte) []byte {
	g, ok := d.groups[groupID]
	if !ok {
		g = &fecGroup{}
		d.groups[groupID] = g
	}

	if frameType == fecFrameData && int(index) < fecGroupSize {
		if g.packets[index] == nil {
			cp := make([]byte, len(payload))
			copy(cp, payload)
			g.packets[index] = cp
			g.received++
			if len(payload) > g.maxLen {
				g.maxLen = len(payload)
			}
		}
	} else if frameType == fecFrameParity {
		cp := make([]byte, len(payload))
		copy(cp, payload)
		g.parity = cp
		if len(payload) > g.maxLen {
			g.maxLen = len(payload)
		}
	}

	// Try to recover: need exactly N-1 data packets + parity.
	if g.parity != nil && g.received == fecGroupSize-1 {
		missing := -1
		for i := 0; i < fecGroupSize; i++ {
			if g.packets[i] == nil {
				missing = i
				break
			}
		}
		if missing >= 0 {
			recovered := make([]byte, g.maxLen)
			copy(recovered, g.parity)
			for i := 0; i < fecGroupSize; i++ {
				if i != missing && g.packets[i] != nil {
					xorInto(recovered, g.packets[i])
				}
			}
			delete(d.groups, groupID)
			return recovered
		}
	}

	// Cleanup complete groups.
	if g.received == fecGroupSize {
		delete(d.groups, groupID)
	}

	// Cleanup stale groups (more than 256 group IDs behind).
	for gid := range d.groups {
		if groupID-gid > 256 {
			delete(d.groups, gid)
		}
	}

	return nil
}

// xorInto XORs src into dst (dst ^= src). dst must be >= len(src).
func xorInto(dst, src []byte) {
	for i := 0; i < len(src) && i < len(dst); i++ {
		dst[i] ^= src[i]
	}
}

// fecFrameWrite writes a single FEC-framed packet.
func fecFrameWrite(w io.Writer, frameType byte, groupID uint16, index byte, payload []byte) error {
	buf := getPktBuf()
	defer putPktBuf(buf)
	b := (*buf)[:fecHeaderSize+len(payload)]
	b[0] = frameType
	binary.LittleEndian.PutUint16(b[1:3], groupID)
	b[3] = index
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(payload)))
	copy(b[fecHeaderSize:], payload)
	_, err := w.Write(b)
	return err
}

// fecFrameRead reads one FEC-framed packet.
func FECFrameRead(r io.Reader) (frameType byte, groupID uint16, index byte, payload []byte, err error) {
	var hdr [fecHeaderSize]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	frameType = hdr[0]
	groupID = binary.LittleEndian.Uint16(hdr[1:3])
	index = hdr[3]
	n := binary.LittleEndian.Uint32(hdr[4:8])
	if n > 65535 {
		err = io.ErrUnexpectedEOF
		return
	}
	payload = make([]byte, n)
	_, err = io.ReadFull(r, payload)
	return
}
