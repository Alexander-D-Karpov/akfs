package logger

import (
	"log"
	"sync"

	"github.com/Alexander-D-Karpov/akfs/backend/internal/config"
)

var (
	level config.LogLevel
	mu    sync.RWMutex
)

func SetLevel(l config.LogLevel) {
	mu.Lock()
	level = l
	mu.Unlock()
}

func GetLevel() config.LogLevel {
	mu.RLock()
	defer mu.RUnlock()
	return level
}

func Debug(format string, args ...interface{}) {
	if GetLevel() <= config.LogLevelDebug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func Info(format string, args ...interface{}) {
	if GetLevel() <= config.LogLevelInfo {
		log.Printf("[INFO] "+format, args...)
	}
}

func Warn(format string, args ...interface{}) {
	if GetLevel() <= config.LogLevelWarn {
		log.Printf("[WARN] "+format, args...)
	}
}

func Error(format string, args ...interface{}) {
	if GetLevel() <= config.LogLevelError {
		log.Printf("[ERROR] "+format, args...)
	}
}
