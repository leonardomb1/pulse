//go:build linux

package node

// io_uring-accelerated TUN reader and writer.
//
// Replaces the standard fd.Read/fd.Write paths in tunManager with batched
// io_uring submissions. The reader pre-fills the SQ with read requests;
// as CQEs complete, packets are routed through the existing per-peer queue
// pipeline. The writer accepts packets and submits batched write SQEs.
//
// Falls back to the standard path if io_uring setup fails (old kernel, seccomp).

import (
	"context"
	"os"
)

// ioUringBatchSize is the number of reads to keep in-flight simultaneously.
const ioUringBatchSize = 64

// tunReaderIOURing replaces tunReader with an io_uring-based reader.
// Pre-submits ioUringBatchSize read SQEs; as each completes, routes the
// packet and resubmits a new read for that buffer slot.
func (t *tunManager) tunReaderIOURing(ctx context.Context, fd *os.File) {
	tunFD := int(fd.Fd())
	ring, err := newIOUring(tunFD, 256, t.node.cfg.Tun.IOURingBufs)
	if err != nil {
		Warnf("tun: io_uring setup failed (%v) — falling back to standard reader", err)
		t.tunReader(ctx, fd)
		return
	}
	defer func() { _ = ring.Close() }()

	Infof("tun: io_uring reader active (ring fd=%d, %d buffers)", ring.fd, ring.bufCount)

	// Pre-fill the SQ with initial read requests.
	inflight := 0
	for i := 0; i < ioUringBatchSize; i++ {
		bufIdx := ring.acquireBuffer()
		if bufIdx < 0 {
			break
		}
		if err := ring.submitRead(bufIdx); err != nil {
			ring.releaseBuffer(bufIdx)
			break
		}
		inflight++
	}

	if inflight == 0 {
		Warnf("tun: io_uring could not submit initial reads — falling back")
		t.tunReader(ctx, fd)
		return
	}

	// Submit the initial batch.
	if err := ring.submit(uint32(inflight)); err != nil {
		Warnf("tun: io_uring initial submit failed: %v — falling back", err)
		t.tunReader(ctx, fd)
		return
	}

	for {
		if ctx.Err() != nil {
			_ = fd.Close()
			return
		}

		// Wait for at least one completion.
		if err := ring.submitAndWait(0); err != nil {
			if ctx.Err() != nil {
				_ = fd.Close()
				return
			}
			// Transient error — retry.
			continue
		}

		// Drain all available CQEs.
		ring.drainCQEs(func(userData uint64, res int32) {
			bufIdx := int(userData)

			if res <= 0 {
				// Read error or zero-length — resubmit the buffer.
				if err := ring.submitRead(bufIdx); err != nil {
					ring.releaseBuffer(bufIdx)
					inflight--
				}
				return
			}

			n := int(res)
			buf := ring.bufferSlice(bufIdx)
			pkt := buf[:n]

			// Validate IPv4 minimum header.
			if n >= 20 && pkt[0]>>4 == 4 {
				t.routeOutbound(pkt)
			}

			// Resubmit a read for this buffer slot.
			if err := ring.submitRead(bufIdx); err != nil {
				ring.releaseBuffer(bufIdx)
				inflight--
			}
		})

		// Submit requeued reads (non-blocking).
		if inflight > 0 {
			_ = ring.submit(0)
		}

		// If we've lost all in-flight buffers, try to recover.
		if inflight <= 0 {
			for i := 0; i < ioUringBatchSize; i++ {
				bufIdx := ring.acquireBuffer()
				if bufIdx < 0 {
					break
				}
				if err := ring.submitRead(bufIdx); err != nil {
					ring.releaseBuffer(bufIdx)
					break
				}
				inflight++
			}
			if inflight > 0 {
				_ = ring.submit(uint32(inflight))
			}
		}
	}
}

// tunWriterIOURing writes a packet to the TUN device using io_uring.
// For single packets this submits one SQE and waits; for batch scenarios
// the caller should use tunBatchWriterIOURing instead.
func tunWriteIOURing(ring *ioUring, pkt []byte) error {
	// Use a high userData value to distinguish write completions from reads.
	const writeUserData = 0xFFFFFFFF

	if err := ring.submitWrite(pkt, writeUserData); err != nil {
		return err
	}
	return ring.submitAndWait(1)
}

// tunPipeWriterIOURing creates an io_uring ring for TUN writes and returns
// a function that writes packets through it. The ring is cleaned up when
// the context is cancelled.
func (t *tunManager) tunPipeWriterIOURing(ctx context.Context, fd *os.File) func(pkt []byte) error {
	tunFD := int(fd.Fd())
	ring, err := newIOUring(tunFD, 64, t.node.cfg.Tun.IOURingBufs)
	if err != nil {
		Debugf("tun: io_uring write ring setup failed: %v — using standard writes", err)
		return nil
	}

	// Clean up ring when context ends.
	go func() {
		<-ctx.Done()
		_ = ring.Close()
	}()

	return func(pkt []byte) error {
		if ring.closed.Load() {
			return os.ErrClosed
		}
		return tunWriteIOURing(ring, pkt)
	}
}
