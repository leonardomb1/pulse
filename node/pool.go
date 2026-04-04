package node

import "sync"

// bufferSize is the copy buffer size. 64KB matches most OS socket buffer sizes
// and gives good throughput without excessive memory use per stream.
const bufferSize = 64 * 1024

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
