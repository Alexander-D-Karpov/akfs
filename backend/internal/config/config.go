package config

import (
	"os"
	"strconv"
)

type Config struct {
	ListenAddr  string
	StoragePath string
	WALPath     string
	MaxFSSize   int64
	AuthToken   string
	EncryptKey  string
	LogLevel    string
}

func Load() *Config {
	return &Config{
		ListenAddr:  getEnv("VTFS_LISTEN", "0.0.0.0:9000"),
		StoragePath: getEnv("VTFS_STORAGE", "/var/lib/vtfs/data.bin"),
		WALPath:     getEnv("VTFS_WAL", "/var/lib/vtfs/data.wal"),
		MaxFSSize:   getEnvInt64("VTFS_MAX_SIZE", 2*1024*1024*1024),
		AuthToken:   getEnv("VTFS_TOKEN", "admin"),
		EncryptKey:  getEnv("VTFS_KEY", "default-encryption-key-32bytes!"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
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
