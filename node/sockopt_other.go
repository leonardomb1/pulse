//go:build !linux

package node

import "syscall"

func setSocketOpts(network, address string, c syscall.RawConn) error {
	return nil // no-op on non-Linux
}
