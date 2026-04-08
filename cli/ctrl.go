package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/leonardomb1/pulse/config"
)

// CtrlDo sends a JSON command to the daemon's control socket and returns the response.
func CtrlDo(socketPath string, cmd interface{}) (map[string]json.RawMessage, error) {
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon socket %s: %w\n(is pulse running?)", socketPath, err)
	}
	defer conn.Close()

	b, _ := json.Marshal(cmd)
	_, _ = conn.Write(append(b, '\n'))

	var result map[string]json.RawMessage
	if err := json.NewDecoder(conn).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if errMsg, ok := result["error"]; ok {
		var s string
		_ = json.Unmarshal(errMsg, &s)
		return nil, fmt.Errorf("%s", s)
	}
	return result, nil
}

// SocketPath resolves the control socket path from flags or defaults.
func SocketPath(args []string) string {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	sock := fs.String("socket", "", "control socket path")
	_ = fs.Parse(args)
	if *sock != "" {
		return *sock
	}
	return config.Defaults().Control.Socket
}
