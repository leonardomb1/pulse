package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"pulse/config"
)

// CtrlDo sends a JSON command to the daemon's control socket and returns the response.
func CtrlDo(socketPath string, cmd interface{}) (map[string]json.RawMessage, error) {
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon socket %s: %w\n(is pulse running?)", socketPath, err)
	}
	defer conn.Close()

	b, _ := json.Marshal(cmd)
	conn.Write(append(b, '\n'))

	var result map[string]json.RawMessage
	if err := json.NewDecoder(conn).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if errMsg, ok := result["error"]; ok {
		var s string
		json.Unmarshal(errMsg, &s)
		return nil, fmt.Errorf("%s", s)
	}
	return result, nil
}

// SocketPath resolves the control socket path from flags or config.
func SocketPath(args []string) string {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	sock := fs.String("socket", "", "control socket path")
	configPath := fs.String("config", "", "path to config.toml")
	fs.Parse(args)
	if *sock != "" {
		return *sock
	}
	cfg, err := config.Load(*configPath)
	if err == nil && cfg.Control.Socket != "" {
		return cfg.Control.Socket
	}
	home, _ := os.UserHomeDir()
	return home + "/.pulse/pulse.sock"
}
