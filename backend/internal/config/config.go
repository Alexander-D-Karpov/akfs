package config

import (
	"os"
	"strconv"
)

type Config struct {
	DatabaseURL string
	Port        string
	LogLevel    string
	AuthToken   string
	MaxFSSize   int64
}

func Load() *Config {
	return &Config{
		DatabaseURL: getEnv("DATABASE_URL", "postgres://vtfs:vtfs@localhost:5432/vtfs?sslmode=disable"),
		Port:        getEnv("PORT", "8080"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		AuthToken:   getEnv("VTFS_TOKEN", "admin"),
		MaxFSSize:   getEnvInt64("VTFS_MAX_SIZE", 2*1024*1024*1024),
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
