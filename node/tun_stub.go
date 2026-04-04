//go:build !linux

package node

import (
	"context"
	"net"
)

type tunStub struct{}

func NewTunDevice(n *Node, devName, meshCIDR string) (TunDevice, error) {
	Warnf("tun: not supported on this platform — tun mode disabled")
	return &tunStub{}, nil
}

func (t *tunStub) Run(ctx context.Context)              { <-ctx.Done() }
func (t *tunStub) HandleInbound(conn net.Conn)          { conn.Close() }
func (t *tunStub) RunPipe(nodeID string, conn net.Conn) { conn.Close() }
func (t *tunStub) RefreshMeshIPs()                      {}

var _ TunDevice = (*tunStub)(nil)
