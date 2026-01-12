package http

import (
	"net/http"
)

func SetupRouter(h *Handler) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/lookup", h.Lookup)
	mux.HandleFunc("POST /api/v1/list", h.List)
	mux.HandleFunc("POST /api/v1/create", h.Create)
	mux.HandleFunc("POST /api/v1/mkdir", h.Mkdir)
	mux.HandleFunc("POST /api/v1/unlink", h.Unlink)
	mux.HandleFunc("POST /api/v1/rmdir", h.Rmdir)
	mux.HandleFunc("POST /api/v1/read", h.Read)
	mux.HandleFunc("POST /api/v1/write", h.Write)
	mux.HandleFunc("POST /api/v1/link", h.Link)
	mux.HandleFunc("GET /health", h.Health)
	mux.HandleFunc("GET /api/v1/stats", h.Stats)

	return LoggingMiddleware(mux)
}
