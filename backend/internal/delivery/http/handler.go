package http

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/Alexander-D-Karpov/akfs/backend/internal/domain"
	"github.com/Alexander-D-Karpov/akfs/backend/internal/usecase"
)

type Handler struct {
	fs        usecase.FilesystemService
	authToken string
	maxFSSize int64
}

func NewHandler(fs usecase.FilesystemService, authToken string, maxFSSize int64) *Handler {
	return &Handler{
		fs:        fs,
		authToken: authToken,
		maxFSSize: maxFSSize,
	}
}

func (h *Handler) isAuthorized(r *http.Request) bool {
	token := r.Header.Get("X-Auth-Token")
	return token == h.authToken
}

type LookupRequest struct {
	ParentIno int64  `json:"parent_ino"`
	Name      string `json:"name"`
}

type ListRequest struct {
	ParentIno int64 `json:"parent_ino"`
}

type ListResponse struct {
	Entries []EntryResponse `json:"entries"`
}

type EntryResponse struct {
	Name string `json:"name"`
	Ino  int64  `json:"ino"`
	Mode uint32 `json:"mode"`
}

type CreateRequest struct {
	ParentIno int64  `json:"parent_ino"`
	Name      string `json:"name"`
	Mode      uint32 `json:"mode"`
}

type UnlinkRequest struct {
	ParentIno int64  `json:"parent_ino"`
	Name      string `json:"name"`
}

type ReadRequest struct {
	Ino    int64 `json:"ino"`
	Offset int64 `json:"offset"`
	Size   int64 `json:"size"`
}

type ReadResponse struct {
	Data  string `json:"data"`
	Bytes int64  `json:"bytes"`
}

type WriteRequest struct {
	Ino    int64  `json:"ino"`
	Offset int64  `json:"offset"`
	Data   string `json:"data"`
}

type WriteResponse struct {
	BytesWritten int64 `json:"bytes_written"`
	NewSize      int64 `json:"new_size"`
}

type LinkRequest struct {
	Ino          int64  `json:"ino"`
	NewParentIno int64  `json:"new_parent_ino"`
	NewName      string `json:"new_name"`
}

type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorResponse{Error: message, Code: code})
}

func handleDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		writeError(w, http.StatusNotFound, "ENOENT", err.Error())
	case errors.Is(err, domain.ErrExists):
		writeError(w, http.StatusConflict, "EEXIST", err.Error())
	case errors.Is(err, domain.ErrNotEmpty):
		writeError(w, http.StatusBadRequest, "ENOTEMPTY", err.Error())
	case errors.Is(err, domain.ErrIsDirectory):
		writeError(w, http.StatusBadRequest, "EISDIR", err.Error())
	case errors.Is(err, domain.ErrNotDirectory):
		writeError(w, http.StatusBadRequest, "ENOTDIR", err.Error())
	case errors.Is(err, domain.ErrInvalidName):
		writeError(w, http.StatusBadRequest, "EINVAL", err.Error())
	case errors.Is(err, domain.ErrPermission):
		writeError(w, http.StatusForbidden, "EPERM", err.Error())
	case errors.Is(err, domain.ErrNoSpace):
		writeError(w, http.StatusInsufficientStorage, "ENOSPC", err.Error())
	default:
		log.Printf("Internal error: %v", err)
		writeError(w, http.StatusInternalServerError, "EIO", "internal error")
	}
}

func (h *Handler) Lookup(w http.ResponseWriter, r *http.Request) {
	var req LookupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "EINVAL", "invalid request body")
		return
	}

	inode, err := h.fs.Lookup(r.Context(), req.ParentIno, req.Name)
	if err != nil {
		handleDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, inode)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	var req ListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "EINVAL", "invalid request body")
		return
	}

	entries, err := h.fs.List(r.Context(), req.ParentIno)
	if err != nil {
		handleDomainError(w, err)
		return
	}

	resp := ListResponse{Entries: make([]EntryResponse, 0, len(entries))}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, EntryResponse{
			Name: e.Name,
			Ino:  e.ChildIno,
			Mode: e.Mode,
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "EACCES", "unauthorized")
		return
	}

	var req CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "EINVAL", "invalid request body")
		return
	}

	inode, err := h.fs.Create(r.Context(), req.ParentIno, req.Name, req.Mode)
	if err != nil {
		handleDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, inode)
}

func (h *Handler) Mkdir(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "EACCES", "unauthorized")
		return
	}

	var req CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "EINVAL", "invalid request body")
		return
	}

	inode, err := h.fs.Mkdir(r.Context(), req.ParentIno, req.Name, req.Mode)
	if err != nil {
		handleDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, inode)
}

func (h *Handler) Unlink(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "EACCES", "unauthorized")
		return
	}

	var req UnlinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "EINVAL", "invalid request body")
		return
	}

	if err := h.fs.Unlink(r.Context(), req.ParentIno, req.Name); err != nil {
		handleDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) Rmdir(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "EACCES", "unauthorized")
		return
	}

	var req UnlinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "EINVAL", "invalid request body")
		return
	}

	if err := h.fs.Rmdir(r.Context(), req.ParentIno, req.Name); err != nil {
		handleDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) Read(w http.ResponseWriter, r *http.Request) {
	var req ReadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "EINVAL", "invalid request body")
		return
	}

	data, bytesRead, err := h.fs.Read(r.Context(), req.Ino, req.Offset, req.Size)
	if err != nil {
		handleDomainError(w, err)
		return
	}

	encoded := base64.StdEncoding.EncodeToString(data)

	writeJSON(w, http.StatusOK, ReadResponse{
		Data:  encoded,
		Bytes: bytesRead,
	})
}

func (h *Handler) Write(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "EACCES", "unauthorized")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "EINVAL", "failed to read body")
		return
	}

	var req WriteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "EINVAL", "invalid request body")
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "EINVAL", "invalid base64 data")
		return
	}

	currentSize, err := h.fs.GetTotalSize(r.Context())
	if err != nil {
		handleDomainError(w, err)
		return
	}

	if currentSize+int64(len(decoded)) > h.maxFSSize {
		writeError(w, http.StatusInsufficientStorage, "ENOSPC", "filesystem full")
		return
	}

	bytesWritten, newSize, err := h.fs.Write(r.Context(), req.Ino, req.Offset, decoded)
	if err != nil {
		handleDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, WriteResponse{
		BytesWritten: bytesWritten,
		NewSize:      newSize,
	})
}

func (h *Handler) Link(w http.ResponseWriter, r *http.Request) {
	if !h.isAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "EACCES", "unauthorized")
		return
	}

	var req LinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "EINVAL", "invalid request body")
		return
	}

	if err := h.fs.Link(r.Context(), req.Ino, req.NewParentIno, req.NewName); err != nil {
		handleDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) Stats(w http.ResponseWriter, r *http.Request) {
	totalSize, err := h.fs.GetTotalSize(r.Context())
	if err != nil {
		handleDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_size": totalSize,
		"max_size":   h.maxFSSize,
		"available":  h.maxFSSize - totalSize,
	})
}
