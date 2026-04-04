//go:build linux

package node

import "golang.org/x/sys/unix"

const soReusePort = unix.SO_REUSEPORT
