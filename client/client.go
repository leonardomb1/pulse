// Package client provides a minimal Go API for applications to open tunnels
// through a local pulse relay node.
//
// The pulse TCP listener accepts connections that start with a single JSON line
// specifying the destination. After sending that line, the connection behaves
// exactly like a direct TCP connection to the target — no pulse-specific framing
// from that point on. Any library or protocol works transparently on top.
//
// Example — connect a database driver through pulse:
//
//	conn, err := client.Dial("localhost:7000", "a3f2c1d4", "localhost:5432")
//	if err != nil { log.Fatal(err) }
//	// hand conn to any library that accepts a net.Conn
//
// Example — dial with a context and timeout:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	conn, err := client.DialContext(ctx, "localhost:7000", "a3f2c1d4", "localhost:22")
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
)

// tunnelRequest is the header sent to the pulse TCP listener.
type tunnelRequest struct {
	DestNode string `json:"dest_node"`
	DestAddr string `json:"dest_addr"`
}

// Dial opens a tunnel through the pulse node at pulseAddr to destAddr on destNode.
//
//   - pulseAddr  — TCP address of the local pulse listener, e.g. "localhost:7000"
//   - destNode   — NodeID of the target relay node (shown on startup or via `pulse status`)
//   - destAddr   — TCP address to reach on the destination node, e.g. "localhost:22"
//
// The returned net.Conn is a transparent tunnel: read/write as if directly connected.
func Dial(pulseAddr, destNode, destAddr string) (net.Conn, error) {
	return DialContext(context.Background(), pulseAddr, destNode, destAddr)
}

// DialContext is like Dial but honours the provided context for the initial connection.
func DialContext(ctx context.Context, pulseAddr, destNode, destAddr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", pulseAddr)
	if err != nil {
		return nil, fmt.Errorf("pulse: connect to %s: %w", pulseAddr, err)
	}

	hdr, _ := json.Marshal(tunnelRequest{DestNode: destNode, DestAddr: destAddr})
	hdr = append(hdr, '\n')
	if _, err := conn.Write(hdr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("pulse: send header: %w", err)
	}

	return conn, nil
}

// Forwarder listens on a local TCP port and tunnels every connection through
// pulse to a fixed destination. Useful for apps that don't support proxy
// settings (e.g. RDP clients, legacy database drivers).
//
//	fwd, _ := client.NewForwarder("localhost:7000", "a3f2c1d4", "localhost:3389")
//	fwd.ListenAndServe(ctx, ":3389")  // RDP client connects to localhost:3389
type Forwarder struct {
	pulseAddr string
	destNode  string
	destAddr  string
}

// NewForwarder creates a Forwarder that maps localPort → pulse → destNode:destAddr.
func NewForwarder(pulseAddr, destNode, destAddr string) *Forwarder {
	return &Forwarder{pulseAddr: pulseAddr, destNode: destNode, destAddr: destAddr}
}

// ListenAndServe starts accepting on localAddr and tunnels each connection.
// Blocks until ctx is cancelled or a fatal listen error occurs.
func (f *Forwarder) ListenAndServe(ctx context.Context, localAddr string) error {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("pulse forwarder: listen %s: %w", localAddr, err)
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go f.handle(conn)
	}
}

func (f *Forwarder) handle(local net.Conn) {
	defer local.Close()

	remote, err := DialContext(context.Background(), f.pulseAddr, f.destNode, f.destAddr)
	if err != nil {
		return
	}
	defer remote.Close()

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 64*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				dst.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go cp(remote, local)
	go cp(local, remote)
	<-done
}
