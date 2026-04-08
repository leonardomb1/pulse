//go:build linux

package tests

import (
	"os"
	"sync"
	"testing"

	"github.com/leonardomb1/pulse/node"
)

// BenchmarkTunReadStandard measures the standard fd.Read path throughput.
// Uses a pipe as a stand-in for a TUN fd to isolate read syscall overhead.
func BenchmarkTunReadStandard(b *testing.B) {
	r, w, err := os.Pipe()
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	pkt := make([]byte, 1400)
	pkt[0] = 0x45
	buf := make([]byte, 2048)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < b.N; i++ {
			if _, err := w.Write(pkt); err != nil {
				return
			}
		}
		_ = w.Close()
	}()

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Read(buf); err != nil {
			break
		}
	}
	b.StopTimer()
	_ = r.Close()
	wg.Wait()
}

// BenchmarkTunWriteStandard measures the standard fd.Write path throughput.
func BenchmarkTunWriteStandard(b *testing.B) {
	r, w, err := os.Pipe()
	if err != nil {
		b.Fatal(err)
	}

	pkt := make([]byte, 1400)
	pkt[0] = 0x45

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			if _, err := r.Read(buf); err != nil {
				return
			}
		}
	}()

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Write(pkt); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	_ = w.Close()
	_ = r.Close()
	wg.Wait()
}

// BenchmarkIOURingBufferAcquireRelease measures the overhead of the
// atomic buffer pool acquire/release cycle.
func BenchmarkIOURingBufferAcquireRelease(b *testing.B) {
	if !node.IOURingAvailable() {
		b.Skip("io_uring not available")
	}

	r, w, err := os.Pipe()
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()

	ring, err := node.NewIOURingForTest(int(w.Fd()), 32)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = ring.Close() }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := ring.AcquireBuffer()
		if idx < 0 {
			b.Fatal("buffer pool exhausted")
		}
		ring.ReleaseBuffer(idx)
	}
}
