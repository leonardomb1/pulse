package node

import "sync"

// bufferSize is the copy buffer size. 256KB allows the bridge to move large
// chunks per syscall, keeping up with the QUIC/yamux receive windows (4-16MB).
const bufferSize = 256 * 1024

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, bufferSize)
		return &b
	},
}

func getBuffer() *[]byte {
	return bufPool.Get().(*[]byte)
}

func putBuffer(b *[]byte) {
	bufPool.Put(b)
}
