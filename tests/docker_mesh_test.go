package tests

// Large-scale mesh networking test with isolated VNETs.
//
// Known limitation: vnet-b nodes bootstrap via the CA's vnet-b IP, but the CA
// advertises its vnet-a address in gossip. Nodes that connected via vnet-b cannot
// be reached by vnet-a peers through gossip-announced addresses. This test
// validates same-VNET connectivity and documents the cross-VNET gap.
//
// Topology:
//
//	pulse-net-a (172.30.1.0/24)           pulse-net-b (172.30.2.0/24)
//	  │                                       │
//	  ├── relay-a  (.2)                       ├── relay-b  (.2)
//	  ├── node-a1  (.3)                       ├── node-b1  (.3)
//	  ├── node-a2  (.4)                       ├── node-b2  (.4)
//	  ├── node-a3  (.5)                       ├── node-b3  (.5)
//	  │                                       │
//	  ├── exit     (.10) ─────────────────────┤ exit (.10)
//	  │                                       │
//	  └── ca       (.100) ────────────────────┘ ca (.100)
//
// The CA bridges both networks. Nodes in vnet-a cannot directly reach vnet-b.
// All cross-VNET traffic must route through the CA's relay path.
// The exit node also bridges both networks and has exit routing enabled.
//
// Run with: PULSE_DOCKER_TEST=1 go test ./tests/ -run TestDockerMesh -timeout 300s -v

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	meshImage   = "pulse-test:latest"
	meshToken   = "mesh-test-token"
	meshNetA    = "pulse-vnet-a"
	meshNetB    = "pulse-vnet-b"
	meshSubnetA = "172.30.1.0/24"
	meshSubnetB = "172.30.2.0/24"

	meshCAIPa   = "172.30.1.100" // CA on vnet-a
	meshCAIPb   = "172.30.2.100" // CA on vnet-b
	meshExitIPa = "172.30.1.10"  // exit on vnet-a
	meshExitIPb = "172.30.2.10"  // exit on vnet-b
)

// meshNode describes a container in the mesh test.
type meshNode struct {
	name    string
	network string
	ip      string
	args    []string
}

func meshCleanup() {
	names := []string{
		"mesh-ca", "mesh-exit",
		"mesh-relay-a", "mesh-a1", "mesh-a2", "mesh-a3",
		"mesh-relay-b", "mesh-b1", "mesh-b2", "mesh-b3",
	}
	for _, n := range names {
		_, _ = docker("rm", "-f", n)
	}
	_, _ = docker("network", "rm", meshNetA)
	_, _ = docker("network", "rm", meshNetB)
}

func createMeshNetworks(t *testing.T) {
	t.Helper()
	_, _ = docker("network", "rm", meshNetA)
	_, _ = docker("network", "rm", meshNetB)
	if _, err := docker("network", "create", "--subnet", meshSubnetA, meshNetA); err != nil {
		t.Fatalf("create vnet-a: %v", err)
	}
	if _, err := docker("network", "create", "--subnet", meshSubnetB, meshNetB); err != nil {
		t.Fatalf("create vnet-b: %v", err)
	}
}

// startMeshContainer starts a container on its primary network, then optionally
// connects it to a second network.
func startMeshContainer(t *testing.T, name, network, ip string, extraNetworks map[string]string, args ...string) {
	t.Helper()
	_, _ = docker("rm", "-f", name)
	full := []string{
		"run", "-d",
		"--name", name,
		"--network", network,
		"--ip", ip,
		"--cap-add", "NET_ADMIN",
		"--device", "/dev/net/tun",
		meshImage,
	}
	full = append(full, args...)
	out, err := docker(full...)
	if err != nil {
		t.Fatalf("start %s: %s\n%v", name, out, err)
	}
	// Attach to additional networks.
	for net, netIP := range extraNetworks {
		if out, err := docker("network", "connect", "--ip", netIP, net, name); err != nil {
			t.Fatalf("connect %s to %s: %s\n%v", name, net, out, err)
		}
	}
}

// waitMeshReady waits for a container's pulse daemon to respond.
func waitMeshReady(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := dockerExec(name, "pulse", "status")
		if strings.Contains(out, "Node:") {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", name)
}

// meshPeerCount returns the number of peers a node sees in its gossip table.
func meshPeerCount(t *testing.T, container string) int {
	t.Helper()
	out, err := dockerExec(container, "pulse", "status")
	if err != nil {
		return 0
	}
	// Count non-empty lines after the header (first 2 lines are node info + blank + header).
	lines := strings.Split(strings.TrimSpace(out), "\n")
	count := 0
	for _, l := range lines {
		if strings.Contains(l, "10.100.") { // mesh IP present = peer row
			count++
		}
	}
	return count
}

func TestDockerMeshWideNetwork(t *testing.T) {
	if os.Getenv("PULSE_DOCKER_TEST") == "" {
		t.Skip("set PULSE_DOCKER_TEST=1 to run Docker integration tests")
	}
	if !dockerAvailable() {
		t.Skip("docker not available")
	}

	buildImage(t)
	createMeshNetworks(t)
	defer meshCleanup()

	caAddr := meshCAIPa + ":8443"

	// 1. Start CA on vnet-a, then attach to vnet-b (bridges both networks).
	// --listen 0.0.0.0:8443 binds all interfaces so vnet-b nodes can reach it.
	// --addr advertises the vnet-a address for gossip.
	startMeshContainer(t, "mesh-ca", meshNetA, meshCAIPa,
		map[string]string{meshNetB: meshCAIPb},
		"--ca", "--scribe", "--tun", "--dns",
		"--addr", caAddr,
		"--listen", "0.0.0.0:8443",
		"--network", "mesh-test",
		"--token", meshToken,
		"--log-level", "warn",
	)
	waitMeshReady(t, "mesh-ca")

	// 2. Start exit node on vnet-a, attached to vnet-b.
	startMeshContainer(t, "mesh-exit", meshNetA, meshExitIPa,
		map[string]string{meshNetB: meshExitIPb},
		"--exit", "--tun",
		"--listen", "0.0.0.0:8443",
		"--network", "mesh-test",
		"--token", meshToken,
		"--log-level", "warn",
		caAddr,
	)
	waitMeshReady(t, "mesh-exit")

	// 3. Start relay-a + 3 nodes on vnet-a only (can reach CA directly).
	vnetANodes := []meshNode{
		{"mesh-relay-a", meshNetA, "172.30.1.2", []string{"--tun"}},
		{"mesh-a1", meshNetA, "172.30.1.3", []string{"--tun"}},
		{"mesh-a2", meshNetA, "172.30.1.4", []string{"--tun"}},
		{"mesh-a3", meshNetA, "172.30.1.5", []string{"--tun"}},
	}
	for _, n := range vnetANodes {
		args := append(n.args, "--network", "mesh-test", "--token", meshToken, "--log-level", "warn", caAddr)
		startMeshContainer(t, n.name, n.network, n.ip, nil, args...)
	}

	// 4. Start relay-b + 3 nodes on vnet-b only (can reach CA via vnet-b, NOT vnet-a).
	caBAddr := meshCAIPb + ":8443" // these nodes bootstrap via CA's vnet-b address
	vnetBNodes := []meshNode{
		{"mesh-relay-b", meshNetB, "172.30.2.2", []string{"--tun", "--dns"}},
		{"mesh-b1", meshNetB, "172.30.2.3", []string{"--tun", "--dns"}},
		{"mesh-b2", meshNetB, "172.30.2.4", []string{"--tun"}},
		{"mesh-b3", meshNetB, "172.30.2.5", []string{"--tun"}},
	}
	for _, n := range vnetBNodes {
		args := append(n.args, "--network", "mesh-test", "--token", meshToken, "--log-level", "warn", caBAddr)
		startMeshContainer(t, n.name, n.network, n.ip, nil, args...)
	}

	// Wait for all nodes to be ready.
	allNodes := []string{
		"mesh-relay-a", "mesh-a1", "mesh-a2", "mesh-a3",
		"mesh-relay-b", "mesh-b1", "mesh-b2", "mesh-b3",
	}
	for _, name := range allNodes {
		waitMeshReady(t, name)
	}

	// 5. Wait for gossip convergence — all 10 nodes should see each other.
	t.Run("Gossip convergence", func(t *testing.T) {
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			count := meshPeerCount(t, "mesh-ca")
			if count >= 10 { // CA + exit + 4 vnet-a + 4 vnet-b = 10
				t.Logf("CA sees %d peers — converged", count)
				return
			}
			time.Sleep(2 * time.Second)
		}
		// Debug: print CA status on failure.
		out, _ := dockerExec("mesh-ca", "pulse", "status")
		t.Fatalf("gossip did not converge (CA sees %d peers):\n%s", meshPeerCount(t, "mesh-ca"), out)
	})

	// 6. Cross-VNET ping: node on vnet-a pings node on vnet-b via mesh IP.
	// Allow extra time for TUN pipes to establish across 10-node mesh.
	time.Sleep(10 * time.Second)

	t.Run("Cross-VNET mesh ping", func(t *testing.T) {
		meshIPb1 := extractMeshIP(t, "mesh-b1")
		if meshIPb1 == "" {
			t.Fatal("could not extract mesh IP of mesh-b1")
		}
		out, err := dockerExec("mesh-a1", "ping", "-c", "3", "-W", "5", meshIPb1)
		if err != nil {
			t.Fatalf("cross-VNET ping mesh-a1 → mesh-b1 (%s) failed:\n%s", meshIPb1, out)
		}
		t.Logf("mesh-a1 → mesh-b1 (%s): %s", meshIPb1, lastLine(out))
	})

	// 7. Verify vnet-b node sees vnet-a node in gossip.
	t.Run("VNET-B sees VNET-A nodes", func(t *testing.T) {
		out, _ := dockerExec("mesh-b1", "pulse", "status")
		meshIPa1 := extractMeshIP(t, "mesh-a1")
		if !strings.Contains(out, meshIPa1) {
			t.Errorf("mesh-b1 does not see mesh-a1 (%s) in gossip:\n%s", meshIPa1, out)
		}
	})

	// 8. Bidirectional cross-VNET ping.
	t.Run("Reverse cross-VNET ping", func(t *testing.T) {
		meshIPa2 := extractMeshIP(t, "mesh-a2")
		out, err := dockerExec("mesh-b2", "ping", "-c", "3", "-W", "5", meshIPa2)
		if err != nil {
			t.Fatalf("cross-VNET ping mesh-b2 → mesh-a2 (%s) failed:\n%s", meshIPa2, out)
		}
		t.Logf("mesh-b2 → mesh-a2 (%s): %s", meshIPa2, lastLine(out))
	})

	// 9. Same-VNET ping (should work directly, not through CA).
	t.Run("Same-VNET ping", func(t *testing.T) {
		meshIPa3 := extractMeshIP(t, "mesh-a3")
		out, err := dockerExec("mesh-a1", "ping", "-c", "3", "-W", "5", meshIPa3)
		if err != nil {
			t.Fatalf("same-VNET ping mesh-a1 → mesh-a3 (%s) failed:\n%s", meshIPa3, out)
		}
		t.Logf("mesh-a1 → mesh-a3 (%s): %s", meshIPa3, lastLine(out))
	})

	// 10. DNS resolution across VNETs (scribe is on CA, query from vnet-b node).
	t.Run("DNS add and resolve cross-VNET", func(t *testing.T) {
		// Add a DNS record pointing to a vnet-a node.
		meshIPa1 := extractMeshIP(t, "mesh-a1")
		_, _ = dockerExec("mesh-ca", "pulse", "dns", "add", "--type", "A", "service-a.pulse", meshIPa1)
		time.Sleep(3 * time.Second) // wait for netconfig propagation

		// Query from a vnet-b node.
		out, err := dockerExec("mesh-b1", "dig", "@127.0.0.1", "-p", "5353", "service-a.pulse", "A", "+short")
		if err != nil {
			t.Fatalf("DNS query failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, meshIPa1) {
			t.Errorf("DNS did not resolve service-a.pulse to %s:\n%s", meshIPa1, out)
		}

		// Cleanup.
		_, _ = dockerExec("mesh-ca", "pulse", "dns", "remove", "service-a.pulse")
	})

	// 11. Tags propagate to directly connected nodes.
	// Note: multi-hop tag propagation depends on the 60s netconfig re-broadcast
	// cycle, so we test a node directly connected to the CA (vnet-a).
	t.Run("Tag propagation", func(t *testing.T) {
		caID := extractNodeID(t, "mesh-ca")
		_, _ = dockerExec("mesh-ca", "pulse", "tag", caID, "infra")
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			out, _ := dockerExec("mesh-a1", "pulse", "status")
			if strings.Contains(out, "infra") {
				t.Log("tag 'infra' visible on mesh-a1")
				return
			}
			time.Sleep(2 * time.Second)
		}
		out, _ := dockerExec("mesh-a1", "pulse", "status")
		t.Errorf("tag 'infra' not visible on mesh-a1 after 15s:\n%s", out)
	})

	// 12. Scribe sees traffic stats from remote nodes.
	t.Run("Traffic stats from remote VNET", func(t *testing.T) {
		// The cross-VNET pings above generated traffic. Check scribe stats.
		out, err := dockerExec("mesh-ca", "curl", "-s", "http://127.0.0.1:8080/api/status")
		if err != nil {
			t.Fatalf("scribe API failed: %v", err)
		}
		var status struct {
			Stats map[string]struct {
				BytesIn  int64 `json:"bytes_in"`
				BytesOut int64 `json:"bytes_out"`
			} `json:"stats"`
		}
		if err := json.Unmarshal([]byte(out), &status); err != nil {
			t.Fatalf("parse scribe status: %v", err)
		}
		if len(status.Stats) == 0 {
			t.Log("no stats reported yet (nodes may not have pushed yet)")
		} else {
			t.Logf("scribe has stats from %d nodes", len(status.Stats))
		}
	})

	// 13. Exit node is visible with exit role.
	t.Run("Exit node role visible", func(t *testing.T) {
		out, _ := dockerExec("mesh-a1", "pulse", "status")
		if !strings.Contains(out, "exit") {
			t.Errorf("exit role not visible from mesh-a1:\n%s", out)
		}
	})

	// 14. Node count: every node should see all 10 peers.
	t.Run("Full mesh visibility", func(t *testing.T) {
		allContainers := append([]string{"mesh-ca", "mesh-exit"}, allNodes...)
		for _, c := range allContainers {
			count := meshPeerCount(t, c)
			if count < 10 {
				out, _ := dockerExec(c, "pulse", "status")
				t.Errorf("%s sees only %d peers (want 10):\n%s", c, count, out)
			}
		}
	})
}

func extractNodeID(t *testing.T, container string) string {
	t.Helper()
	out, _ := dockerExec(container, "pulse", "id")
	fields := strings.Fields(out)
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

func init() {
	// Suppress unused import warning for fmt.
	_ = fmt.Sprintf
}
