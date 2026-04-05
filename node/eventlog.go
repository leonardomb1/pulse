package node

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// EventType identifies the kind of event being logged.
type EventType string

const (
	// Node lifecycle.
	EventStartup  EventType = "startup"
	EventShutdown EventType = "shutdown"

	// Link events.
	EventLinkUp   EventType = "link_up"
	EventLinkDown EventType = "link_down"

	// NAT punch.
	EventNATPunchSuccess EventType = "nat_punch_success"
	EventNATPunchFail    EventType = "nat_punch_fail"

	// Certificate lifecycle.
	EventCertRenew         EventType = "cert_renew"
	EventCertExpiryWarning EventType = "cert_expiry_warning"

	// CA operations.
	EventJoinAttempted EventType = "join_attempted"
	EventCertIssued    EventType = "cert_issued"
	EventJoinFailed    EventType = "join_failed"
	EventCertRevoked   EventType = "cert_revoked"

	// Scribe operations.
	EventNetconfigBroadcast EventType = "netconfig_broadcast"
	EventACLChanged         EventType = "acl_changed"
	EventDNSChanged         EventType = "dns_changed"
	EventTagChanged         EventType = "tag_changed"
	EventNodeRevoked        EventType = "node_revoked"

	// Event log rotation threshold.
	eventLogMaxBytes = 10 * 1024 * 1024 // 10 MB
)

// EventEntry is one line in the event log.
type EventEntry struct {
	Timestamp time.Time `json:"ts"`
	Type      EventType `json:"type"`
	NodeID    string    `json:"node_id,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// EventLog is a buffered, append-only JSONL event log with rotation.
// Writes are buffered and flushed periodically (not fsynced per write)
// for minimal impact on the data path.
type EventLog struct {
	mu   sync.Mutex
	f    *os.File
	buf  *bufio.Writer
	path string
	size int64

	subMu       sync.Mutex
	subscribers []chan EventEntry
}

// OpenEventLog opens (or creates) the event log at path.
func OpenEventLog(path string) (*EventLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &EventLog{
		f:    f,
		buf:  bufio.NewWriterSize(f, 4096),
		path: path,
		size: info.Size(),
	}, nil
}

// Emit appends one event to the log. Buffered, not fsynced.
func (l *EventLog) Emit(e EventEntry) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')

	l.mu.Lock()
	_, _ = l.buf.Write(b)
	l.size += int64(len(b))
	if l.size >= eventLogMaxBytes {
		l.rotateLocked()
	}
	l.mu.Unlock()

	// Fan out to live subscribers (pulse logs).
	l.subMu.Lock()
	for _, ch := range l.subscribers {
		select {
		case ch <- e:
		default: // drop if subscriber is slow
		}
	}
	l.subMu.Unlock()
}

// Flush writes buffered data to disk.
func (l *EventLog) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.buf.Flush()
}

// Close flushes and closes the log file.
func (l *EventLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.buf.Flush()
	return l.f.Close()
}

// rotateLocked renames the current file to .1 and opens a new one.
// Must be called with l.mu held.
func (l *EventLog) rotateLocked() {
	_ = l.buf.Flush()
	l.f.Close()
	_ = os.Rename(l.path, l.path+".1")
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	l.f = f
	l.buf = bufio.NewWriterSize(f, 4096)
	l.size = 0
}

// Subscribe returns a channel that receives new events as they are emitted.
// Call Unsubscribe to stop receiving and free resources.
func (l *EventLog) Subscribe() chan EventEntry {
	ch := make(chan EventEntry, 64)
	l.subMu.Lock()
	l.subscribers = append(l.subscribers, ch)
	l.subMu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel.
func (l *EventLog) Unsubscribe(ch chan EventEntry) {
	l.subMu.Lock()
	defer l.subMu.Unlock()
	for i, c := range l.subscribers {
		if c == ch {
			l.subscribers = append(l.subscribers[:i], l.subscribers[i+1:]...)
			close(ch)
			return
		}
	}
}

// FilterOpts controls which events are returned by ReadFiltered.
type FilterOpts struct {
	Type  EventType
	Node  string
	Since time.Time
}

// ReadFiltered reads the log file and returns matching events.
func ReadFiltered(path string, opts FilterOpts) ([]EventEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []EventEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e EventEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		if opts.Type != "" && e.Type != opts.Type {
			continue
		}
		if opts.Node != "" && e.NodeID != opts.Node {
			continue
		}
		if !opts.Since.IsZero() && e.Timestamp.Before(opts.Since) {
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
