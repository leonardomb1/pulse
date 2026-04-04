package node

import (
	"log"
	"strings"
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
