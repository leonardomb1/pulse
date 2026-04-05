package node

import "sync/atomic"

// TrafficCounters tracks bytes transferred and active connections across
// all tunnels and SOCKS proxied streams on this node.
type TrafficCounters struct {
	BytesIn     atomic.Int64
	BytesOut    atomic.Int64
	ActiveConns atomic.Int64
}
