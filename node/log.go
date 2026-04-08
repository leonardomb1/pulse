package node

import (
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// LogLevel controls the verbosity of pulse's logging.
type LogLevel int32

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

var logLevel int32 = int32(LevelInfo)

// SetLogLevel sets the global log level.
func SetLogLevel(l LogLevel) {
	atomic.StoreInt32(&logLevel, int32(l))
}

// ParseLogLevel maps a string to a LogLevel.
func ParseLogLevel(s string) LogLevel {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug
	case "info", "":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

const logMaxBytes = 10 * 1024 * 1024 // 10 MB

// RotatingWriter wraps a file with automatic rotation at logMaxBytes.
type RotatingWriter struct {
	mu   sync.Mutex
	f    *os.File
	path string
	size int64
}

// NewRotatingWriter opens a log file with rotation support.
func NewRotatingWriter(path string) (*RotatingWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	info, _ := f.Stat()
	size := int64(0)
	if info != nil {
		size = info.Size()
	}
	return &RotatingWriter{f: f, path: path, size: size}, nil
}

func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.f.Write(p)
	w.size += int64(n)
	if w.size >= logMaxBytes {
		w.f.Close()
		_ = os.Rename(w.path, w.path+".1")
		f, ferr := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if ferr == nil {
			w.f = f
			w.size = 0
		}
	}
	return n, err
}

// SetupLogFile configures the global logger to write to a rotating file.
func SetupLogFile(path string) error {
	w, err := NewRotatingWriter(path)
	if err != nil {
		return err
	}
	log.SetOutput(w)
	return nil
}

func Debugf(format string, args ...any) {
	if atomic.LoadInt32(&logLevel) <= int32(LevelDebug) {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func Infof(format string, args ...any) {
	if atomic.LoadInt32(&logLevel) <= int32(LevelInfo) {
		log.Printf(format, args...)
	}
}

func Warnf(format string, args ...any) {
	if atomic.LoadInt32(&logLevel) <= int32(LevelWarn) {
		log.Printf("[WARN] "+format, args...)
	}
}

func Errorf(format string, args ...any) {
	if atomic.LoadInt32(&logLevel) <= int32(LevelError) {
		log.Printf("[ERROR] "+format, args...)
	}
}
