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
	fecDefaultGroupSize = 10 // data packets per FEC group (legacy default)
	fecFrameData        = 0
	fecFrameParity      = 1
	fecHeaderSize       = 8 // type(1) + groupID(2) + index(1) + length(4)
)

// fecEncoder generates parity packets for outbound TUN traffic.
type fecEncoder struct {
	groupID   uint16
	idx       int
	groupSize int // data packets per FEC group
	parity    []byte
	maxLen    int // longest packet in this group (parity must be this long)
}

// NewFECEncoder creates an encoder with the given group size.
// Use groupSize=0 to get the default (10).
func NewFECEncoder(groupSize int) *fecEncoder {
	if groupSize <= 0 {
		groupSize = fecDefaultGroupSize
	}
	return &fecEncoder{groupSize: groupSize, parity: make([]byte, 65535)}
}

// GroupSize returns the current group size of the encoder.
func (e *fecEncoder) GroupSize() int {
	return e.groupSize
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
	if e.idx >= e.groupSize {
		parityReady = true
	}
	return
}

// FlushParity writes the parity packet and resets for the next group.
// The index byte encodes the group size: index = 128 + groupSize.
// Legacy decoders see index >= 128 which is not a valid data index, so they
// treat it as parity. New decoders extract groupSize = index - 128.
// Special case: index=255 is the legacy encoding (groupSize=10).
func (e *fecEncoder) FlushParity(w io.Writer) error {
	idx := byte(128 + e.groupSize)
	err := fecFrameWrite(w, fecFrameParity, e.groupID, idx, e.parity[:e.maxLen])
	e.groupID++
	e.idx = 0
	e.maxLen = 0
	for i := range e.parity {
		e.parity[i] = 0
	}
	return err
}

// Pending returns true if the encoder has buffered data packets that haven't
// been flushed as parity yet (partial group).
func (e *fecEncoder) Pending() bool {
	return e.idx > 0
}

// fecDecoder reconstructs lost packets from parity.
type fecDecoder struct {
	groups map[uint16]*fecGroup
}

type fecGroup struct {
	packets      [][]byte // nil slots = not yet received; grown as needed
	parity       []byte
	received     int
	expectedSize int // group size (set when parity arrives); 0 = unknown
	maxLen       int
}

func NewFECDecoder() *fecDecoder {
	return &fecDecoder{groups: make(map[uint16]*fecGroup)}
}

// fecParityGroupSize extracts the group size from a parity frame's index byte.
//   - index == 255: legacy encoding, group size = 10
//   - index >= 128: new encoding, group size = index - 128
func fecParityGroupSize(index byte) int {
	if index == 255 {
		return fecDefaultGroupSize // legacy
	}
	return int(index) - 128
}

// Add processes a received FEC frame. Returns a reconstructed packet if one
// was recovered, or nil if no recovery needed/possible.
func (d *fecDecoder) Add(frameType byte, groupID uint16, index byte, payload []byte) []byte {
	g, ok := d.groups[groupID]
	if !ok {
		g = &fecGroup{}
		d.groups[groupID] = g
	}

	if frameType == fecFrameData && index < 128 {
		idx := int(index)
		// Grow packets slice if needed.
		if idx >= len(g.packets) {
			newSlice := make([][]byte, idx+1)
			copy(newSlice, g.packets)
			g.packets = newSlice
		}
		if g.packets[idx] == nil {
			cp := make([]byte, len(payload))
			copy(cp, payload)
			g.packets[idx] = cp
			g.received++
			if len(payload) > g.maxLen {
				g.maxLen = len(payload)
			}
		}
	} else if frameType == fecFrameParity {
		cp := make([]byte, len(payload))
		copy(cp, payload)
		g.parity = cp
		g.expectedSize = fecParityGroupSize(index)
		if len(payload) > g.maxLen {
			g.maxLen = len(payload)
		}
	}

	// Try to recover: need exactly N-1 data packets + parity, and we must
	// know the expected group size (from parity frame).
	if g.parity != nil && g.expectedSize > 0 && g.received == g.expectedSize-1 {
		// Ensure packets slice covers the full group.
		if len(g.packets) < g.expectedSize {
			newSlice := make([][]byte, g.expectedSize)
			copy(newSlice, g.packets)
			g.packets = newSlice
		}
		missing := -1
		for i := 0; i < g.expectedSize; i++ {
			if g.packets[i] == nil {
				missing = i
				break
			}
		}
		if missing >= 0 {
			recovered := make([]byte, g.maxLen)
			copy(recovered, g.parity)
			for i := 0; i < g.expectedSize; i++ {
				if i != missing && g.packets[i] != nil {
					xorInto(recovered, g.packets[i])
				}
			}
			delete(d.groups, groupID)
			return recovered
		}
	}

	// Cleanup complete groups (all data received, no recovery needed).
	if g.expectedSize > 0 && g.received >= g.expectedSize {
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

// FECGroupSizeForLoss returns the optimal FEC group size for a given packet
// loss rate. Returns 0 to disable FEC when loss is negligible.
func FECGroupSizeForLoss(lossRate float64) int {
	switch {
	case lossRate < 0.01:
		return 0 // FEC disabled — negligible loss
	case lossRate < 0.05:
		return 20 // ~5% overhead
	case lossRate < 0.10:
		return 10 // ~10% overhead
	case lossRate < 0.20:
		return 5 // ~20% overhead
	default:
		return 3 // ~33% overhead — high loss environment
	}
}

// xorInto XORs src into dst (dst ^= src). dst must be >= len(src).
func xorInto(dst, src []byte) {
	for i := 0; i < len(src) && i < len(dst); i++ {
		dst[i] ^= src[i]
	}
}

// ExportFECFrameWrite is an exported alias for fecFrameWrite, used by tests.
func ExportFECFrameWrite(w io.Writer, frameType byte, groupID uint16, index byte, payload []byte) error {
	return fecFrameWrite(w, frameType, groupID, index, payload)
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
