package config

import (
	"os"
	"strconv"
	"strings"
)

type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

type Config struct {
	ListenAddr  string
	HTTPAddr    string
	StoragePath string
	WALPath     string
	MaxFSSize   int64
	AuthToken   string
	EncryptKey  string
	LogLevel    LogLevel
	EnableHTTP  bool
}

func Load() *Config {
	return &Config{
		ListenAddr:  getEnv("VTFS_LISTEN", "0.0.0.0:9000"),
		HTTPAddr:    getEnv("VTFS_HTTP", "0.0.0.0:8080"),
		StoragePath: getEnv("VTFS_STORAGE", "/var/lib/vtfs/data.bin"),
		WALPath:     getEnv("VTFS_WAL", "/var/lib/vtfs/data.wal"),
		MaxFSSize:   getEnvInt64("VTFS_MAX_SIZE", 2*1024*1024*1024),
		AuthToken:   getEnv("VTFS_TOKEN", "admin"),
		EncryptKey:  getEnv("VTFS_KEY", "default-encryption-key-32bytes!"),
		LogLevel:    parseLogLevel(getEnv("LOG_LEVEL", "info")),
		EnableHTTP:  getEnvBool("VTFS_HTTP_ENABLE", true),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.ParseInt(value, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		v := strings.ToLower(value)
		return v == "true" || v == "1" || v == "yes"
	}
	return defaultValue
}

func parseLogLevel(level string) LogLevel {
	switch strings.ToLower(level) {
	case "debug":
		return LogLevelDebug
	case "info":
		return LogLevelInfo
	case "warn", "warning":
		return LogLevelWarn
	case "error":
		return LogLevelError
	default:
		return LogLevelInfo
	}
}
