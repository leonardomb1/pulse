package tui

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// ctrlDo sends a JSON command to the daemon's control socket and returns the response.
func ctrlDo(socketPath string, cmd interface{}) (map[string]json.RawMessage, error) {
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w (is pulse running?)", socketPath, err)
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
