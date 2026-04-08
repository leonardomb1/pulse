//go:build linux

package node

// io_uring wrapper for high-throughput TUN I/O.
//
// Uses raw syscalls via golang.org/x/sys/unix — no external dependency.
// Requires kernel ≥5.1 (io_uring_setup). Features used:
//   - IORING_OP_READ / IORING_OP_WRITE for TUN fd I/O
//   - Registered buffers (IORING_REGISTER_BUFFERS) for zero-copy kernel→user
//   - Batched SQE submission + CQE harvesting
//
// Design: one ring per TUN queue fd. The ring owns a fixed buffer pool.
// The caller submits read SQEs; the kernel fills buffers asynchronously.
// CQEs are drained in batches — one kernel entry per N packets instead of N.

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// io_uring constants not yet in golang.org/x/sys/unix.
const (
	iouringOpRead  = 22 // IORING_OP_READ (since 5.6)
	iouringOpWrite = 23 // IORING_OP_WRITE (since 5.6)

	iouringEnterGetEvents = 1 << 0 // IORING_ENTER_GETEVENTS
)

// ioUring manages a single io_uring instance bound to one fd.
type ioUring struct {
	fd      int // io_uring fd from io_uring_setup
	tunFD   int // TUN file descriptor for I/O
	entries uint32

	// Submission queue (SQ).
	sqRing    []byte
	sqes      []ioUringSQE
	sqHead    unsafe.Pointer // *uint32, kernel-updated
	sqTail    unsafe.Pointer // *uint32, user-updated
	sqMask    uint32
	sqEntries uint32
	sqArray   unsafe.Pointer // *uint32 array (SQ index → SQE index)

	// Completion queue (CQ).
	cqRing    []byte
	cqHead    unsafe.Pointer // *uint32, user-updated
	cqTail    unsafe.Pointer // *uint32, kernel-updated
	cqMask    uint32
	cqEntries uint32
	cqes      unsafe.Pointer // *ioUringCQE array

	// Registered buffer pool.
	bufPool  []byte       // contiguous buffer pool
	bufSize  int          // size of each individual buffer
	bufCount int          // number of buffers
	bufInUse []int32      // per-buffer in-use flag (atomic)
	iovecs   []unix.Iovec // for IORING_REGISTER_BUFFERS

	closed atomic.Bool
}

// ioUringSQE is the submission queue entry (64 bytes).
type ioUringSQE struct {
	Opcode      uint8
	Flags       uint8
	IoPrio      uint16
	Fd          int32
	Off         uint64
	Addr        uint64
	Len         uint32
	OpcodeFlags uint32
	UserData    uint64
	BufIndex    uint16
	Personality uint16
	SpliceFdIn  int32
	Addr3       uint64
	_pad2       [1]uint64
}

// ioUringCQE is the completion queue entry (16 bytes).
type ioUringCQE struct {
	UserData uint64
	Res      int32
	Flags    uint32
}

// ioUringParams is passed to io_uring_setup.
type ioUringParams struct {
	SqEntries    uint32
	CqEntries    uint32
	Flags        uint32
	SqThreadCPU  uint32
	SqThreadIdle uint32
	Features     uint32
	WqFd         uint32
	Resv         [3]uint32
	SqOff        ioUringSqRingOffsets
	CqOff        ioUringCqRingOffsets
}

type ioUringSqRingOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Flags       uint32
	Dropped     uint32
	Array       uint32
	Resv1       uint32
	UserAddr    uint64
}

type ioUringCqRingOffsets struct {
	Head        uint32
	Tail        uint32
	RingMask    uint32
	RingEntries uint32
	Overflow    uint32
	Cqes        uint32
	Flags       uint32
	Resv1       uint32
	UserAddr    uint64
}

const (
	sqeSize = 64
	cqeSize = 16
)

// ioUringBufferSize is the size of each registered buffer (MTU + headroom).
const ioUringBufferSize = 2048

// ioUringBufferCount is the number of pre-registered buffers per ring.
const ioUringBufferCount = 256

// newIOUring creates an io_uring instance for the given TUN file descriptor.
// entries must be a power of 2 (typically 256 or 512).
func newIOUring(tunFD int, entries uint32) (*ioUring, error) {
	params := ioUringParams{}
	ringFD, _, errno := unix.Syscall(
		unix.SYS_IO_URING_SETUP,
		uintptr(entries),
		uintptr(unsafe.Pointer(&params)),
		0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("io_uring_setup: %w", errno)
	}

	ring := &ioUring{
		fd:        int(ringFD),
		tunFD:     tunFD,
		entries:   entries,
		sqEntries: params.SqOff.RingEntries,
		cqEntries: params.CqOff.RingEntries,
		bufSize:   ioUringBufferSize,
		bufCount:  ioUringBufferCount,
	}

	if err := ring.mapRings(&params); err != nil {
		_ = unix.Close(ring.fd)
		return nil, err
	}

	if err := ring.setupBuffers(); err != nil {
		_ = ring.Close()
		return nil, err
	}

	return ring, nil
}

// mapRings maps the SQ and CQ rings into userspace.
func (r *ioUring) mapRings(params *ioUringParams) error {
	sqOff := &params.SqOff
	cqOff := &params.CqOff

	// Map SQ ring.
	sqRingSize := sqOff.Array + sqOff.RingEntries*4 // array of uint32
	sqRing, err := unix.Mmap(r.fd, 0, int(sqRingSize),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return fmt.Errorf("mmap sq ring: %w", err)
	}
	r.sqRing = sqRing

	r.sqHead = unsafe.Pointer(&sqRing[sqOff.Head])
	r.sqTail = unsafe.Pointer(&sqRing[sqOff.Tail])
	r.sqMask = *(*uint32)(unsafe.Pointer(&sqRing[sqOff.RingMask]))
	r.sqArray = unsafe.Pointer(&sqRing[sqOff.Array])

	// Read actual SQ entries count from mapped memory.
	r.sqEntries = *(*uint32)(unsafe.Pointer(&sqRing[sqOff.RingEntries]))

	// Map SQEs (separate mmap region).
	sqeRegionSize := int(r.sqEntries) * sqeSize
	sqeRegion, err := unix.Mmap(r.fd, 0x10000000, sqeRegionSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		_ = unix.Munmap(sqRing)
		return fmt.Errorf("mmap sqes: %w", err)
	}
	r.sqes = unsafe.Slice((*ioUringSQE)(unsafe.Pointer(&sqeRegion[0])), r.sqEntries)

	// Map CQ ring.
	cqRingSize := cqOff.Cqes + cqOff.RingEntries*uint32(cqeSize)
	cqRing, err := unix.Mmap(r.fd, 0x8000000, int(cqRingSize),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		_ = unix.Munmap(sqeRegion)
		_ = unix.Munmap(sqRing)
		return fmt.Errorf("mmap cq ring: %w", err)
	}
	r.cqRing = cqRing

	r.cqHead = unsafe.Pointer(&cqRing[cqOff.Head])
	r.cqTail = unsafe.Pointer(&cqRing[cqOff.Tail])
	r.cqMask = *(*uint32)(unsafe.Pointer(&cqRing[cqOff.RingMask]))
	r.cqEntries = *(*uint32)(unsafe.Pointer(&cqRing[cqOff.RingEntries]))
	r.cqes = unsafe.Pointer(&cqRing[cqOff.Cqes])

	return nil
}

// setupBuffers allocates and registers a contiguous buffer pool with the kernel.
func (r *ioUring) setupBuffers() error {
	r.bufPool = make([]byte, r.bufSize*r.bufCount)
	r.bufInUse = make([]int32, r.bufCount)
	r.iovecs = make([]unix.Iovec, r.bufCount)

	for i := 0; i < r.bufCount; i++ {
		base := unsafe.Pointer(&r.bufPool[i*r.bufSize])
		r.iovecs[i] = unix.Iovec{
			Base: (*byte)(base),
			Len:  uint64(r.bufSize),
		}
	}

	_, _, errno := unix.Syscall6(
		unix.SYS_IO_URING_REGISTER,
		uintptr(r.fd),
		0, // IORING_REGISTER_BUFFERS
		uintptr(unsafe.Pointer(&r.iovecs[0])),
		uintptr(r.bufCount),
		0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("io_uring_register buffers: %w", errno)
	}

	return nil
}

// acquireBuffer claims a buffer from the pool. Returns the index or -1 if full.
func (r *ioUring) acquireBuffer() int {
	for i := 0; i < r.bufCount; i++ {
		if atomic.CompareAndSwapInt32(&r.bufInUse[i], 0, 1) {
			return i
		}
	}
	return -1
}

// releaseBuffer returns a buffer to the pool.
func (r *ioUring) releaseBuffer(idx int) {
	atomic.StoreInt32(&r.bufInUse[idx], 0)
}

// bufferSlice returns the byte slice for a registered buffer.
func (r *ioUring) bufferSlice(idx int) []byte {
	off := idx * r.bufSize
	return r.bufPool[off : off+r.bufSize]
}

// submitRead submits a read SQE for the TUN fd into a registered buffer.
// userData encodes the buffer index for CQE correlation.
func (r *ioUring) submitRead(bufIdx int) error {
	tail := atomic.LoadUint32((*uint32)(r.sqTail))
	head := atomic.LoadUint32((*uint32)(r.sqHead))

	if tail-head >= r.sqEntries {
		return fmt.Errorf("SQ full")
	}

	idx := tail & r.sqMask
	sqe := &r.sqes[idx]
	*sqe = ioUringSQE{} // zero out
	sqe.Opcode = iouringOpRead
	sqe.Fd = int32(r.tunFD)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(&r.bufPool[bufIdx*r.bufSize])))
	sqe.Len = uint32(r.bufSize)
	sqe.Off = ^uint64(0) // -1 = use current file offset
	sqe.UserData = uint64(bufIdx)

	// Write SQ array entry.
	sqArr := (*[1 << 20]uint32)(r.sqArray)
	sqArr[idx] = uint32(idx)

	// Memory barrier: ensure SQE is visible before updating tail.
	atomic.StoreUint32((*uint32)(r.sqTail), tail+1)

	return nil
}

// submitWrite submits a write SQE for the TUN fd from a buffer.
func (r *ioUring) submitWrite(data []byte, userData uint64) error {
	tail := atomic.LoadUint32((*uint32)(r.sqTail))
	head := atomic.LoadUint32((*uint32)(r.sqHead))

	if tail-head >= r.sqEntries {
		return fmt.Errorf("SQ full")
	}

	idx := tail & r.sqMask
	sqe := &r.sqes[idx]
	*sqe = ioUringSQE{}
	sqe.Opcode = iouringOpWrite
	sqe.Fd = int32(r.tunFD)
	sqe.Addr = uint64(uintptr(unsafe.Pointer(&data[0])))
	sqe.Len = uint32(len(data))
	sqe.Off = ^uint64(0)
	sqe.UserData = userData

	sqArr := (*[1 << 20]uint32)(r.sqArray)
	sqArr[idx] = uint32(idx)

	atomic.StoreUint32((*uint32)(r.sqTail), tail+1)

	return nil
}

// enter calls io_uring_enter to submit pending SQEs and optionally wait for CQEs.
// toSubmit: number of SQEs to submit. minComplete: minimum CQEs to wait for (0 = non-blocking).
func (r *ioUring) enter(toSubmit, minComplete uint32) error {
	var flags uint32
	if minComplete > 0 {
		flags |= iouringEnterGetEvents
	}

	_, _, errno := unix.Syscall6(
		unix.SYS_IO_URING_ENTER,
		uintptr(r.fd),
		uintptr(toSubmit),
		uintptr(minComplete),
		uintptr(flags),
		0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// peekCQE returns the next completed CQE without blocking, or nil if empty.
func (r *ioUring) peekCQE() *ioUringCQE {
	head := atomic.LoadUint32((*uint32)(r.cqHead))
	tail := atomic.LoadUint32((*uint32)(r.cqTail))

	if head == tail {
		return nil
	}

	idx := head & r.cqMask
	cqe := (*ioUringCQE)(unsafe.Add(r.cqes, uintptr(idx)*cqeSize))
	return cqe
}

// advanceCQ advances the CQ head by one, consuming the previously peeked CQE.
func (r *ioUring) advanceCQ() {
	head := atomic.LoadUint32((*uint32)(r.cqHead))
	atomic.StoreUint32((*uint32)(r.cqHead), head+1)
}

// drainCQEs processes all available CQEs, calling fn for each.
// Returns the number of CQEs drained.
func (r *ioUring) drainCQEs(fn func(userData uint64, res int32)) int {
	count := 0
	for {
		cqe := r.peekCQE()
		if cqe == nil {
			break
		}
		fn(cqe.UserData, cqe.Res)
		r.advanceCQ()
		count++
	}
	return count
}

// submitAndWait submits all pending SQEs and waits for at least one CQE.
func (r *ioUring) submitAndWait(toSubmit uint32) error {
	return r.enter(toSubmit, 1)
}

// submit submits all pending SQEs without waiting for completions.
func (r *ioUring) submit(toSubmit uint32) error {
	return r.enter(toSubmit, 0)
}

// Close tears down the io_uring instance.
func (r *ioUring) Close() error {
	if r.closed.Swap(true) {
		return nil
	}

	// Unregister buffers (best-effort during teardown).
	_, _, _ = unix.Syscall6(
		unix.SYS_IO_URING_REGISTER,
		uintptr(r.fd),
		1, // IORING_UNREGISTER_BUFFERS
		0, 0, 0, 0,
	)

	// Unmap rings.
	if r.sqRing != nil {
		_ = unix.Munmap(r.sqRing)
	}
	if r.cqRing != nil {
		_ = unix.Munmap(r.cqRing)
	}

	return unix.Close(r.fd)
}

// IOURingAvailable checks whether io_uring is supported on this kernel.
// Attempts a minimal io_uring_setup and tears it down immediately.
// Exported for testing; internal callers use ioUringAvailable.
func IOURingAvailable() bool {
	return ioUringAvailable()
}

func ioUringAvailable() bool {
	params := ioUringParams{}
	fd, _, errno := unix.Syscall(
		unix.SYS_IO_URING_SETUP,
		4, // minimal entries
		uintptr(unsafe.Pointer(&params)),
		0,
	)
	if errno != 0 {
		return false
	}
	_ = unix.Close(int(fd))
	return true
}

// ExportIOURing wraps an ioUring for external test packages.
type ExportIOURing struct {
	ring *ioUring
}

// NewIOURingForTest creates a ring for testing.
func NewIOURingForTest(fd int, entries uint32) (*ExportIOURing, error) {
	ring, err := newIOUring(fd, entries)
	if err != nil {
		return nil, err
	}
	return &ExportIOURing{ring: ring}, nil
}

// Close tears down the ring.
func (e *ExportIOURing) Close() error { return e.ring.Close() }

// AcquireBuffer claims a buffer from the pool.
func (e *ExportIOURing) AcquireBuffer() int { return e.ring.acquireBuffer() }

// ReleaseBuffer returns a buffer to the pool.
func (e *ExportIOURing) ReleaseBuffer(idx int) { e.ring.releaseBuffer(idx) }

// BufCount returns the number of registered buffers.
func (e *ExportIOURing) BufCount() int { return e.ring.bufCount }
