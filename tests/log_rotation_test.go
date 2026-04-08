package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leonardomb1/pulse/node"
)

func TestRotatingWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := node.NewRotatingWriter(path)
	if err != nil {
		t.Fatal(err)
	}

	// Write some lines.
	for i := 0; i < 100; i++ {
		_, _ = w.Write([]byte("hello world\n"))
	}

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 100 {
		t.Errorf("expected 100 lines, got %d", len(lines))
	}
}

func TestRotatingWriterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := node.NewRotatingWriter(path)
	if err != nil {
		t.Fatal(err)
	}

	// Write enough to trigger rotation (>10MB).
	line := strings.Repeat("x", 10000) + "\n"
	for i := 0; i < 1100; i++ {
		_, _ = w.Write([]byte(line))
	}

	// Rotated file should exist.
	if _, err := os.Stat(path + ".1"); os.IsNotExist(err) {
		t.Error("rotated file .1 not created")
	}

	// Current file should be small.
	info, _ := os.Stat(path)
	if info.Size() > 5*1024*1024 {
		t.Errorf("current file too large after rotation: %d bytes", info.Size())
	}
}

func TestSetupLogFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pulse.log")

	// Write directly through the RotatingWriter instead of hijacking the global logger.
	w, err := node.NewRotatingWriter(path)
	if err != nil {
		t.Fatal(err)
	}

	msg := "test log message 42\n"
	_, _ = w.Write([]byte(msg))

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "test log message 42") {
		t.Errorf("log message not found in file: %q", string(data))
	}
}
