package tests

import (
	"bytes"
	"github.com/leonardomb1/pulse/node"
	"testing"
)

func TestFECEncodeDecodeNoLoss(t *testing.T) {
	var buf bytes.Buffer
	enc := node.NewFECEncoder(10)

	// Write 10 data packets.
	packets := make([][]byte, 10)
	for i := range packets {
		packets[i] = []byte{byte(i), byte(i + 1), byte(i + 2), byte(i + 3)}
		ready, err := enc.AddAndWrite(&buf, packets[i])
		if err != nil {
			t.Fatalf("AddAndWrite %d: %v", i, err)
		}
		if i < 9 && ready {
			t.Fatal("parity ready too early")
		}
		if i == 9 && !ready {
			t.Fatal("parity should be ready after 10 packets")
		}
	}
	_ = enc.FlushParity(&buf)

	// Read back all frames.
	dec := node.NewFECDecoder()
	for i := 0; i < 11; i++ { // 10 data + 1 parity
		ft, gid, idx, payload, err := node.FECFrameRead(&buf)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		recovered := dec.Add(ft, gid, idx, payload)
		if recovered != nil {
			t.Fatal("no recovery needed when all packets present")
		}
	}
}

func TestFECRecoverSingleLoss(t *testing.T) {
	var buf bytes.Buffer
	enc := node.NewFECEncoder(10)

	packets := make([][]byte, 10)
	for i := range packets {
		packets[i] = []byte{byte(i * 10), byte(i*10 + 1), byte(i*10 + 2)}
		_, _ = enc.AddAndWrite(&buf, packets[i])
	}
	_ = enc.FlushParity(&buf)

	// Read all frames, but skip packet index 3 (simulate loss).
	dec := node.NewFECDecoder()
	var recovered []byte
	for i := 0; i < 11; i++ {
		ft, gid, idx, payload, err := node.FECFrameRead(&buf)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		if ft == 0 && idx == 3 {
			continue // simulate loss
		}
		r := dec.Add(ft, gid, idx, payload)
		if r != nil {
			recovered = r
		}
	}

	if recovered == nil {
		t.Fatal("expected recovery of lost packet")
	}
	if !bytes.Equal(recovered[:len(packets[3])], packets[3]) {
		t.Errorf("recovered %v, want %v", recovered[:len(packets[3])], packets[3])
	}
}

func TestFECGroupSizeForLoss(t *testing.T) {
	tests := []struct {
		loss     float64
		wantSize int
	}{
		{0.0, 0},   // no loss -> FEC disabled
		{0.005, 0}, // 0.5% -> still disabled
		{0.01, 20}, // 1% -> large groups (low overhead)
		{0.03, 20}, // 3% -> still large groups
		{0.05, 10}, // 5% -> medium groups
		{0.08, 10}, // 8% -> still medium
		{0.10, 5},  // 10% -> small groups
		{0.15, 5},  // 15% -> still small
		{0.20, 3},  // 20% -> smallest groups
		{0.50, 3},  // 50% -> still smallest
	}
	for _, tt := range tests {
		got := node.FECGroupSizeForLoss(tt.loss)
		if got != tt.wantSize {
			t.Errorf("FECGroupSizeForLoss(%v) = %d, want %d", tt.loss, got, tt.wantSize)
		}
	}
}

func TestFECVariableGroupSize(t *testing.T) {
	for _, groupSize := range []int{3, 5, 10, 20} {
		t.Run("", func(t *testing.T) {
			var buf bytes.Buffer
			enc := node.NewFECEncoder(groupSize)

			if enc.GroupSize() != groupSize {
				t.Fatalf("GroupSize() = %d, want %d", enc.GroupSize(), groupSize)
			}

			// Write exactly groupSize data packets.
			packets := make([][]byte, groupSize)
			for i := range packets {
				packets[i] = make([]byte, 10+i) // variable length
				for j := range packets[i] {
					packets[i][j] = byte(i*17 + j)
				}
				ready, err := enc.AddAndWrite(&buf, packets[i])
				if err != nil {
					t.Fatalf("AddAndWrite %d: %v", i, err)
				}
				if i < groupSize-1 && ready {
					t.Fatalf("parity ready too early at index %d", i)
				}
				if i == groupSize-1 && !ready {
					t.Fatalf("parity should be ready after %d packets", groupSize)
				}
			}
			_ = enc.FlushParity(&buf)

			// Read all frames, drop one data packet, verify recovery.
			dropIdx := groupSize / 2
			dec := node.NewFECDecoder()
			var recovered []byte
			for i := 0; i < groupSize+1; i++ {
				ft, gid, idx, payload, err := node.FECFrameRead(&buf)
				if err != nil {
					t.Fatalf("read frame %d: %v", i, err)
				}
				if ft == 0 && int(idx) == dropIdx {
					continue // simulate loss
				}
				r := dec.Add(ft, gid, idx, payload)
				if r != nil {
					recovered = r
				}
			}

			if recovered == nil {
				t.Fatalf("groupSize=%d: expected recovery of lost packet", groupSize)
			}
			if !bytes.Equal(recovered[:len(packets[dropIdx])], packets[dropIdx]) {
				t.Errorf("groupSize=%d: recovered wrong data", groupSize)
			}
		})
	}
}

func TestFECBackwardCompat(t *testing.T) {
	// Simulate a legacy encoder that writes parity with index=255.
	// The new decoder should treat this as groupSize=10.
	var buf bytes.Buffer

	// Manually write 10 data frames + 1 parity frame with legacy index=255.
	packets := make([][]byte, 10)
	parity := make([]byte, 4)
	for i := range packets {
		packets[i] = []byte{byte(i * 7), byte(i*7 + 1), byte(i*7 + 2), byte(i*7 + 3)}
		// XOR into parity.
		for j := range packets[i] {
			if j < len(parity) {
				parity[j] ^= packets[i][j]
			}
		}
	}

	// Write using the low-level frame writer with legacy index=255 for parity.
	for i, pkt := range packets {
		if err := node.ExportFECFrameWrite(&buf, 0, 0, byte(i), pkt); err != nil {
			t.Fatalf("write data %d: %v", i, err)
		}
	}
	if err := node.ExportFECFrameWrite(&buf, 1, 0, 255, parity); err != nil {
		t.Fatal("write parity:", err)
	}

	// Drop packet 5 and verify recovery with new decoder.
	dec := node.NewFECDecoder()
	var recovered []byte
	for i := 0; i < 11; i++ {
		ft, gid, idx, payload, err := node.FECFrameRead(&buf)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		if ft == 0 && idx == 5 {
			continue // simulate loss
		}
		r := dec.Add(ft, gid, idx, payload)
		if r != nil {
			recovered = r
		}
	}

	if recovered == nil {
		t.Fatal("expected recovery with legacy parity (index=255)")
	}
	if !bytes.Equal(recovered[:len(packets[5])], packets[5]) {
		t.Errorf("recovered %v, want %v", recovered[:len(packets[5])], packets[5])
	}
}
