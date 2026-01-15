package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Alexander-D-Karpov/akfs/backend/internal/config"
	"github.com/Alexander-D-Karpov/akfs/backend/internal/crypto"
	httpserver "github.com/Alexander-D-Karpov/akfs/backend/internal/http"
	"github.com/Alexander-D-Karpov/akfs/backend/internal/logger"
	"github.com/Alexander-D-Karpov/akfs/backend/internal/server"
	"github.com/Alexander-D-Karpov/akfs/backend/internal/storage"
)

func main() {
	cfg := config.Load()

	logger.SetLevel(cfg.LogLevel)

	log.Printf("AKFS Server starting...")
	log.Printf("Listen address: %s", cfg.ListenAddr)
	log.Printf("HTTP address: %s (enabled: %v)", cfg.HTTPAddr, cfg.EnableHTTP)
	log.Printf("Storage path: %s", cfg.StoragePath)
	log.Printf("Max FS size: %d bytes", cfg.MaxFSSize)

	storageDir := filepath.Dir(cfg.StoragePath)
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		log.Fatalf("Failed to create storage directory: %v", err)
	}

	store, err := storage.NewStorage(cfg.StoragePath, cfg.MaxFSSize)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	key := crypto.DeriveKey(cfg.EncryptKey)

	srv, err := server.NewServer(store, key, cfg.AuthToken, cfg.MaxFSSize)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(cfg.ListenAddr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	var httpSrv *httpserver.HTTPServer
	if cfg.EnableHTTP {
		httpSrv = httpserver.NewHTTPServer(store)
		if err := httpSrv.Start(cfg.HTTPAddr); err != nil {
			log.Printf("Warning: Failed to start HTTP server: %v", err)
		}
	}

	log.Printf("Server started successfully")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	if httpSrv != nil {
		httpSrv.Stop()
	}
	srv.Stop()
	log.Println("Server stopped")
}
