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

// SaveNodeState atomically writes a signed node config to state.dat.
func SaveNodeState(dataDir string, snc SignedNodeConfig) error {
	data, err := json.MarshalIndent(snc, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dataDir, "state.dat")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadNodeState reads state.dat from dataDir. Returns nil, nil if the file doesn't exist.
func LoadNodeState(dataDir string) (*SignedNodeConfig, error) {
	data, err := os.ReadFile(filepath.Join(dataDir, "state.dat"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var snc SignedNodeConfig
	if err := json.Unmarshal(data, &snc); err != nil {
		return nil, err
	}
	return &snc, nil
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
