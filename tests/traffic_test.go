package tests

import (
	"net"
	"testing"
	"time"

	"github.com/leonardomb1/pulse/node"
)

func TestTrafficCounters(t *testing.T) {
	var tc node.TrafficCounters

	if tc.BytesIn.Load() != 0 || tc.BytesOut.Load() != 0 || tc.ActiveConns.Load() != 0 {
		t.Fatal("counters should start at zero")
	}

	tc.BytesIn.Add(100)
	tc.BytesOut.Add(200)
	tc.ActiveConns.Add(1)

	if tc.BytesIn.Load() != 100 {
		t.Errorf("BytesIn = %d, want 100", tc.BytesIn.Load())
	}
	if tc.BytesOut.Load() != 200 {
		t.Errorf("BytesOut = %d, want 200", tc.BytesOut.Load())
	}
	if tc.ActiveConns.Load() != 1 {
		t.Errorf("ActiveConns = %d, want 1", tc.ActiveConns.Load())
	}

	tc.ActiveConns.Add(-1)
	if tc.ActiveConns.Load() != 0 {
		t.Errorf("ActiveConns after decrement = %d, want 0", tc.ActiveConns.Load())
	}
}

func TestBridgeDirectCounted(t *testing.T) {
	// Create two pipe pairs. a↔b will be bridged.
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()

	var tc node.TrafficCounters

	payload := []byte("hello from A to B")

	done := make(chan struct{})
	go func() {
		defer close(done)
		node.BridgeDirectCounted(a2, b1, &tc)
	}()

	// Send data from a1 side, close to signal EOF.
	_, _ = a1.Write(payload)
	a1.Close()

	// Read from b2 side.
	buf := make([]byte, 1024)
	n, _ := b2.Read(buf)
	if string(buf[:n]) != string(payload) {
		t.Errorf("got %q, want %q", buf[:n], payload)
	}

	// Close b2 to let the b1→a2 direction finish (EOF).
	b2.Close()

	// Wait for bridge to finish (both directions must complete).
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("bridge did not finish in time")
	}

	// ActiveConns should be back to 0 immediately after bridge returns.
	if tc.ActiveConns.Load() != 0 {
		t.Errorf("ActiveConns = %d, want 0", tc.ActiveConns.Load())
	}

	// BytesOut should reflect data flowing a2→b1 (a1 wrote payload).
	if tc.BytesOut.Load() < int64(len(payload)) {
		t.Errorf("BytesOut = %d, want >= %d", tc.BytesOut.Load(), len(payload))
	}
}
