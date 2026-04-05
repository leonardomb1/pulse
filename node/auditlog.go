package node

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// AuditOp identifies the type of CA operation being logged.
type AuditOp string

const (
	AuditJoinAttempted AuditOp = "join_attempted"
	AuditCertIssued    AuditOp = "cert_issued"
	AuditJoinFailed    AuditOp = "join_failed"
	AuditCertRevoked   AuditOp = "cert_revoked"
)

// AuditEntry is one line in the audit log.
type AuditEntry struct {
	Timestamp  time.Time `json:"ts"`
	Op         AuditOp   `json:"op"`
	NodeID     string    `json:"node_id,omitempty"`
	RemoteAddr string    `json:"remote_addr,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// AuditLog is an append-only newline-delimited JSON file.
// Each Write is fsynced so no entries are lost on crash.
type AuditLog struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// OpenAuditLog opens (or creates) the audit log at path.
func OpenAuditLog(path string) (*AuditLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &AuditLog{f: f, path: path}, nil
}

// Write appends one entry to the log and fsyncs.
func (a *AuditLog) Write(e AuditEntry) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, _ = a.f.Write(b)
	_, _ = a.f.Write([]byte{'\n'})
	return a.f.Sync()
}

func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.f.Close()
}

// ReadAll returns every entry in the log.
func (a *AuditLog) ReadAll() ([]AuditEntry, error) {
	return a.readWhere(func(AuditEntry) bool { return true })
}

// ReadSince returns entries at or after t.
func (a *AuditLog) ReadSince(t time.Time) ([]AuditEntry, error) {
	return a.readWhere(func(e AuditEntry) bool { return !e.Timestamp.Before(t) })
}

// ReadByNode returns entries for a specific node ID.
func (a *AuditLog) ReadByNode(nodeID string) ([]AuditEntry, error) {
	return a.readWhere(func(e AuditEntry) bool { return e.NodeID == nodeID })
}

func (a *AuditLog) readWhere(keep func(AuditEntry) bool) ([]AuditEntry, error) {
	f, err := os.Open(a.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []AuditEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		if keep(e) {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}
