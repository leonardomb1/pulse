package tests

import (
	"github.com/leonardomb1/pulse/node"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  node.LogLevel
	}{
		{"debug", node.LevelDebug},
		{"DEBUG", node.LevelDebug},
		{"info", node.LevelInfo},
		{"", node.LevelInfo},
		{"warn", node.LevelWarn},
		{"warning", node.LevelWarn},
		{"error", node.LevelError},
		{"unknown", node.LevelInfo}, // fallback
	}
	for _, tt := range tests {
		got := node.ParseLogLevel(tt.input)
		if got != tt.want {
			t.Errorf("ParseLogLevel(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestSetLogLevel(t *testing.T) {
	// Just verify it doesn't panic.
	node.SetLogLevel(node.LevelDebug)
	node.SetLogLevel(node.LevelError)
	node.SetLogLevel(node.LevelInfo) // restore
}
