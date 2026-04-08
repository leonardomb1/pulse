//go:build !linux

package node

// ioUringAvailable returns false on non-Linux platforms.
func ioUringAvailable() bool { return false }

// IOURingAvailable is the exported version for tests.
func IOURingAvailable() bool { return false }
