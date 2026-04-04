package tests

import (
	"bytes"
	"github.com/leonardomb1/pulse/node"
	"testing"
)

func TestFECEncodeDecodeNoLoss(t *testing.T) {
	var buf bytes.Buffer
	enc := node.NewFECEncoder()

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
	enc.FlushParity(&buf)

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
	enc := node.NewFECEncoder()

	packets := make([][]byte, 10)
	for i := range packets {
		packets[i] = []byte{byte(i * 10), byte(i*10 + 1), byte(i*10 + 2)}
		enc.AddAndWrite(&buf, packets[i])
	}
	enc.FlushParity(&buf)

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
