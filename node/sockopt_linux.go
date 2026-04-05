//go:build linux

package node

import (
	"syscall"

	"golang.org/x/sys/unix"
)

const soReusePort = unix.SO_REUSEPORT

func setSocketOpts(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
}
