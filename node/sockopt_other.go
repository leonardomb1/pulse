//go:build !linux

package node

import "syscall"

// SO_REUSEPORT is Linux-specific. On other platforms fall back to SO_REUSEADDR
// which is already set separately, so this constant just needs to be defined.
const soReusePort = syscall.SO_REUSEADDR
