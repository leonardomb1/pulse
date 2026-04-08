package tests

// Fleet management E2E test: signed state, config templates, version reporting,
// node groups, and bulk operations.
//
// Topology:
//
//	fleet-net (172.30.5.0/24):
//	  fleet-ca     (.100) — CA + scribe
//	  fleet-gw1    (.2)   — gateway node (tagged "gateway")
//	  fleet-gw2    (.3)   — gateway node (tagged "gateway")
//	  fleet-sensor (.4)   — sensor node (tagged "sensor")
//
// Run with: PULSE_DOCKER_TEST=1 go test ./tests/ -run TestDockerFleet -timeout 300s -v

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	fleetNet    = "pulse-fleet-net"
	fleetSubnet = "172.30.5.0/24"
	fleetCAIP   = "172.30.5.100"
	fleetGW1IP  = "172.30.5.2"
	fleetGW2IP  = "172.30.5.3"
	fleetSenIP  = "172.30.5.4"
	fleetToken  = "fleet-test-token"
)

func fleetCleanup() {
	for _, n := range []string{"fleet-ca", "fleet-gw1", "fleet-gw2", "fleet-sensor"} {
		_, _ = docker("rm", "-f", n)
	}
	_, _ = docker("network", "rm", fleetNet)
}

// fleetAPI calls the scribe HTTP API on the CA container.
func fleetAPI(t *testing.T, method, path string, body interface{}) (int, map[string]json.RawMessage) {
	t.Helper()
	var bodyStr string
	if body != nil {
		b, _ := json.Marshal(body)
		bodyStr = string(b)
	}
	args := []string{"exec", "fleet-ca", "curl", "-s", "-o", "/tmp/resp.json", "-w", "%{http_code}",
		"-X", method, "http://127.0.0.1:8080" + path}
	if bodyStr != "" {
		args = append(args, "-H", "Content-Type: application/json", "-d", bodyStr)
	}
	out, err := docker(args...)
	if err != nil {
		t.Fatalf("API %s %s: %v\n%s", method, path, err, out)
	}
	code := 0
	_, _ = fmt.Sscanf(out, "%d", &code)

	// Read response body.
	respBody, _ := dockerExec("fleet-ca", "cat", "/tmp/resp.json")
	var result map[string]json.RawMessage
	_ = json.Unmarshal([]byte(respBody), &result)
	return code, result
}

func TestDockerFleetManagement(t *testing.T) {
	if os.Getenv("PULSE_DOCKER_TEST") == "" {
		t.Skip("set PULSE_DOCKER_TEST=1 to run Docker integration tests")
	}
	if !dockerAvailable() {
		t.Skip("docker not available")
	}

	buildImage(t)
	defer fleetCleanup()

	_, _ = docker("network", "rm", fleetNet)
	if _, err := docker("network", "create", "--subnet", fleetSubnet, fleetNet); err != nil {
		t.Fatalf("create network: %v", err)
	}

	caAddr := fleetCAIP + ":8443"

	// Start CA + scribe.
	startMeshContainer(t, "fleet-ca", fleetNet, fleetCAIP, nil,
		"--ca", "--scribe", "--tun",
		"--addr", caAddr,
		"--network", "fleet-test",
		"--token", fleetToken,
		"--log-level", "warn",
	)
	waitMeshReady(t, "fleet-ca")

	// Start gateway nodes.
	for _, gw := range []struct{ name, ip string }{
		{"fleet-gw1", fleetGW1IP},
		{"fleet-gw2", fleetGW2IP},
	} {
		startMeshContainer(t, gw.name, fleetNet, gw.ip, nil,
			"--tun",
			"--addr", gw.ip+":8443",
			"--network", "fleet-test",
			"--token", fleetToken,
			"--log-level", "warn",
			caAddr,
		)
	}

	// Start sensor node.
	startMeshContainer(t, "fleet-sensor", fleetNet, fleetSenIP, nil,
		"--tun",
		"--addr", fleetSenIP+":8443",
		"--network", "fleet-test",
		"--token", fleetToken,
		"--log-level", "warn",
		caAddr,
	)

	waitMeshReady(t, "fleet-gw1")
	waitMeshReady(t, "fleet-gw2")
	waitMeshReady(t, "fleet-sensor")

	// Wait for gossip convergence.
	time.Sleep(10 * time.Second)

	// Get node IDs.
	gw1ID := extractNodeID(t, "fleet-gw1")
	gw2ID := extractNodeID(t, "fleet-gw2")
	senID := extractNodeID(t, "fleet-sensor")

	// --- Tag nodes ---
	_, _ = dockerExec("fleet-ca", "pulse", "tag", gw1ID, "gateway")
	_, _ = dockerExec("fleet-ca", "pulse", "tag", gw2ID, "gateway")
	_, _ = dockerExec("fleet-ca", "pulse", "tag", senID, "sensor")
	time.Sleep(3 * time.Second)

	// 1. Version reporting.
	t.Run("Version in status", func(t *testing.T) {
		out, _ := dockerExec("fleet-ca", "pulse", "status")
		// All nodes should report a version (the test binary reports "dev" or the build version).
		lines := strings.Split(out, "\n")
		versionSeen := 0
		for _, l := range lines {
			// Look for version column — it's between HOPS and ROLES.
			if strings.Contains(l, "v0.") || strings.Contains(l, "dev") {
				versionSeen++
			}
		}
		if versionSeen == 0 {
			t.Errorf("no version seen in status output:\n%s", out)
		}
		t.Logf("version visible in %d lines", versionSeen)
	})

	// 2. Node detail API.
	t.Run("Node detail API", func(t *testing.T) {
		code, resp := fleetAPI(t, "GET", "/api/node/"+gw1ID, nil)
		if code != http.StatusOK {
			t.Fatalf("node detail returned %d", code)
		}
		var nodeID string
		_ = json.Unmarshal(resp["node_id"], &nodeID)
		if nodeID != gw1ID {
			t.Errorf("node_id = %q, want %q", nodeID, gw1ID)
		}
		t.Logf("node detail: %s", resp)
	})

	// 3. Groups API.
	t.Run("Groups API", func(t *testing.T) {
		code, resp := fleetAPI(t, "GET", "/api/groups", nil)
		if code != http.StatusOK {
			t.Fatalf("groups returned %d", code)
		}
		var gwCount int
		_ = json.Unmarshal(resp["gateway"], &gwCount)
		var senCount int
		_ = json.Unmarshal(resp["sensor"], &senCount)
		if gwCount != 2 {
			t.Errorf("gateway count = %d, want 2", gwCount)
		}
		if senCount != 1 {
			t.Errorf("sensor count = %d, want 1", senCount)
		}
		t.Logf("groups: gateway=%d sensor=%d", gwCount, senCount)
	})

	// 4. Config templates — create a template for gateways.
	t.Run("Config template create and apply", func(t *testing.T) {
		tmpl := map[string]interface{}{
			"pattern": "gateway",
			"config": map[string]interface{}{
				"tun_enabled": true,
				"log_level":   "debug",
			},
		}
		code, _ := fleetAPI(t, "POST", "/api/templates", tmpl)
		if code != http.StatusNoContent {
			t.Fatalf("template create returned %d", code)
		}

		// Verify template was stored.
		code, resp := fleetAPI(t, "GET", "/api/templates", nil)
		if code != http.StatusOK {
			t.Fatalf("template list returned %d", code)
		}
		respStr := string(resp["gateway"])
		if !strings.Contains(respStr, "tun_enabled") {
			t.Errorf("template not found in response: %s", resp)
		}
		t.Logf("templates: %s", resp)
	})

	// 5. Bulk operations — push config to all gateways.
	t.Run("Bulk push config", func(t *testing.T) {
		bulk := map[string]interface{}{
			"pattern": "gateway",
			"action":  "push_config",
		}
		code, resp := fleetAPI(t, "POST", "/api/bulk", bulk)
		if code != http.StatusOK {
			body, _ := json.Marshal(resp)
			t.Fatalf("bulk push returned %d: %s", code, body)
		}
		var matched int
		_ = json.Unmarshal(resp["matched"], &matched)
		if matched != 2 {
			t.Errorf("bulk matched %d, want 2", matched)
		}
		t.Logf("bulk push: matched=%d", matched)
	})

	// 6. Manual mesh IP assignment.
	t.Run("Mesh IP assignment", func(t *testing.T) {
		ip := map[string]string{"node_id": senID, "mesh_ip": "10.100.99.99"}
		code, _ := fleetAPI(t, "PUT", "/api/mesh-ip", ip)
		if code != http.StatusNoContent {
			t.Fatalf("mesh-ip set returned %d", code)
		}

		// Wait for netconfig propagation.
		time.Sleep(5 * time.Second)

		// Verify the sensor's mesh IP changed in status.
		out, _ := dockerExec("fleet-ca", "pulse", "status")
		if !strings.Contains(out, "10.100.99.99") {
			t.Errorf("mesh IP 10.100.99.99 not visible in status:\n%s", out)
		}
	})

	// 7. Remote restart.
	t.Run("Remote restart", func(t *testing.T) {
		restart := map[string]string{"node_id": senID}
		code, _ := fleetAPI(t, "POST", "/api/remote/restart", restart)
		if code != http.StatusNoContent {
			t.Fatalf("remote restart returned %d", code)
		}
		// The sensor will stop. Wait and check if it recovers (it won't auto-restart
		// in Docker — just verify the command was accepted).
		t.Log("remote restart command accepted")
	})

	// 8. Signed state persistence — verify state.dat exists on gw1.
	t.Run("State file persisted", func(t *testing.T) {
		out, err := dockerExec("fleet-gw1", "cat", "/root/.pulse/state.dat")
		if err != nil {
			t.Fatalf("state.dat not found on fleet-gw1: %v", err)
		}
		if !strings.Contains(out, "sig") || !strings.Contains(out, "scribe_id") {
			t.Errorf("state.dat doesn't look signed:\n%s", out)
		}
		t.Logf("state.dat present and signed (%d bytes)", len(out))
	})

	// 9. Bulk restart all sensors.
	t.Run("Bulk restart by tag", func(t *testing.T) {
		bulk := map[string]interface{}{
			"pattern": "sensor",
			"action":  "restart",
		}
		code, resp := fleetAPI(t, "POST", "/api/bulk", bulk)
		if code != http.StatusOK {
			body, _ := json.Marshal(resp)
			t.Fatalf("bulk restart returned %d: %s", code, body)
		}
		var matched int
		_ = json.Unmarshal(resp["matched"], &matched)
		if matched != 1 {
			t.Errorf("bulk matched %d, want 1", matched)
		}
		t.Logf("bulk restart: matched=%d", matched)
	})

	// 10. Template delete.
	t.Run("Template delete", func(t *testing.T) {
		del := map[string]string{"pattern": "gateway"}
		code, _ := fleetAPI(t, "DELETE", "/api/templates", del)
		if code != http.StatusNoContent {
			t.Fatalf("template delete returned %d", code)
		}
		code, resp := fleetAPI(t, "GET", "/api/templates", nil)
		if code != http.StatusOK {
			t.Fatalf("template list returned %d", code)
		}
		respStr := string(resp["gateway"])
		if respStr != "" {
			t.Errorf("template still present after delete: %s", resp)
		}
	})
}
