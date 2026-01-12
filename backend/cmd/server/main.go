package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Alexander-D-Karpov/akfs/backend/internal/config"
	handler "github.com/Alexander-D-Karpov/akfs/backend/internal/delivery/http"
	"github.com/Alexander-D-Karpov/akfs/backend/internal/repository/postgres"
	"github.com/Alexander-D-Karpov/akfs/backend/internal/usecase"
)

func main() {
	cfg := config.Load()

	log.Printf("Starting with token: %s, max size: %d bytes", cfg.AuthToken, cfg.MaxFSSize)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	cancel()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(context.Background()); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	log.Println("Connected to database")

	repo := postgres.NewRepository(pool)
	fsService := usecase.NewFilesystemService(repo)
	h := handler.NewHandler(fsService, cfg.AuthToken, cfg.MaxFSSize)
	router := handler.SetupRouter(h)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("Server starting on port %s", cfg.Port)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Server stopped")
}
