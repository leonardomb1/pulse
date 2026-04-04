package node

import (
	"bufio"
	"io"
	"net"
)

// copyBuf copies from src to dst using a pooled buffer.
func copyBuf(dst io.Writer, src io.Reader) {
	buf := getBuffer()
	defer putBuffer(buf)
	io.CopyBuffer(dst, src, *buf)
}

// bridge copies bidirectionally between left (with a pre-read bufio.Reader) and right.
//
// Zero-copy fast path: when both underlying connections are *net.TCPConn and
// the bufio.Reader has no buffered bytes, Go's io.Copy internally calls
// TCPConn.ReadFrom which invokes the kernel splice(2) syscall on Linux —
// data moves kernel-buffer to kernel-buffer without touching userspace.
//
// For all other cases (yamux streams, QUIC streams) we fall back to pooled
// 64KB buffer copies, which avoids GC churn from per-copy allocations.
func bridge(leftReader *bufio.Reader, left io.ReadWriter, right net.Conn) {
	// Fast path: drain the bufio buffer first (it holds the already-read header).
	// If the underlying left conn is a raw TCPConn and the buffer is now empty,
	// extract the raw conn so Go can use splice for the remaining data.
	if leftReader.Buffered() == 0 {
		if tc, ok := left.(interface{ RawConn() net.Conn }); ok {
			rawLeft := tc.RawConn()
			if _, isRaw := rawLeft.(*net.TCPConn); isRaw {
				if _, isRaw := right.(*net.TCPConn); isRaw {
					// Both sides are raw TCP — splice path.
					bridgeTCP(rawLeft.(*net.TCPConn), right.(*net.TCPConn))
					return
				}
			}
		}
	}

	// General path: pooled buffer copy.
	done := make(chan struct{}, 2)
	go func() { copyBuf(right, leftReader); done <- struct{}{} }()
	go func() { copyBuf(left, right); done <- struct{}{} }()
	<-done
}

// bridgeTCP uses io.Copy between two *net.TCPConn.
// On Linux, Go's runtime detects this pair and uses splice(2) automatically.
func bridgeTCP(left, right *net.TCPConn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(right, left); right.CloseWrite(); done <- struct{}{} }()
	go func() { io.Copy(left, right); left.CloseWrite(); done <- struct{}{} }()
	<-done
}

// bridgeStreams copies bidirectionally between left (bufio-wrapped) and right (io.ReadWriter).
// Used when right is a yamux/QUIC stream (not a net.Conn), so splice is not possible.
func bridgeStreams(leftReader *bufio.Reader, left io.ReadWriter, right io.ReadWriter) {
	done := make(chan struct{}, 2)
	go func() { copyBuf(right, leftReader); done <- struct{}{} }()
	go func() { copyBuf(left, right); done <- struct{}{} }()
	<-done
}
