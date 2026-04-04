package node

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func peersFilePath(dataDir string) string {
	return filepath.Join(dataDir, "peers.json")
}

// SavePeers atomically writes entries to peers.json in dataDir.
func SavePeers(dataDir string, entries []PeerEntry) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	path := peersFilePath(dataDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadPeers reads peers.json from dataDir. Returns nil, nil if the file doesn't exist yet.
func LoadPeers(dataDir string) ([]PeerEntry, error) {
	data, err := os.ReadFile(peersFilePath(dataDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []PeerEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}
