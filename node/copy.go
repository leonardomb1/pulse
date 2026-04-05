package node

import (
	"bufio"
	"io"
	"net"
	"sync/atomic"
)

// copyBufCounted copies from src to dst using a pooled buffer and adds the byte count to counter.
func copyBufCounted(dst io.Writer, src io.Reader, counter *atomic.Int64) {
	buf := getBuffer()
	defer putBuffer(buf)
	n, _ := io.CopyBuffer(dst, src, *buf)
	counter.Add(n)
}

// bridgeCounted copies bidirectionally between left (with a pre-read bufio.Reader)
// and right, tracking bytes through traffic counters.
func bridgeCounted(leftReader *bufio.Reader, left io.ReadWriter, right net.Conn, tc *TrafficCounters) {
	tc.ActiveConns.Add(1)
	defer tc.ActiveConns.Add(-1)

	done := make(chan struct{}, 2)
	go func() { copyBufCounted(right, leftReader, &tc.BytesOut); done <- struct{}{} }()
	go func() { copyBufCounted(left, right, &tc.BytesIn); done <- struct{}{} }()
	<-done
	<-done
}

// bridgeStreamsCounted copies bidirectionally between left (bufio-wrapped) and
// right (io.ReadWriter), tracking bytes through traffic counters.
func bridgeStreamsCounted(leftReader *bufio.Reader, left io.ReadWriter, right io.ReadWriter, tc *TrafficCounters) {
	tc.ActiveConns.Add(1)
	defer tc.ActiveConns.Add(-1)

	done := make(chan struct{}, 2)
	go func() { copyBufCounted(right, leftReader, &tc.BytesOut); done <- struct{}{} }()
	go func() { copyBufCounted(left, right, &tc.BytesIn); done <- struct{}{} }()
	<-done
	<-done
}

// BridgeDirectCounted copies between two net.Conn bidirectionally using pooled
// buffers, tracking bytes through traffic counters.
func BridgeDirectCounted(a, b net.Conn, tc *TrafficCounters) {
	tc.ActiveConns.Add(1)
	defer tc.ActiveConns.Add(-1)

	done := make(chan struct{}, 2)
	go func() { copyBufCounted(b, a, &tc.BytesOut); done <- struct{}{} }()
	go func() { copyBufCounted(a, b, &tc.BytesIn); done <- struct{}{} }()
	<-done
	<-done
}
