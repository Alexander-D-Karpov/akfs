package http

import (
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Alexander-D-Karpov/akfs/backend/internal/logger"
	"github.com/Alexander-D-Karpov/akfs/backend/internal/storage"
)

type HTTPServer struct {
	storage *storage.Storage
	server  *http.Server
}

type dirEntry struct {
	Name    string
	IsDir   bool
	Size    int64
	ModTime time.Time
}

const indexTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Index of {{.Path}}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        h1 {
            margin: 0;
            padding: 20px;
            background: #2c3e50;
            color: white;
            font-size: 1.2em;
            font-weight: 500;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px 20px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #666;
            font-size: 0.85em;
            text-transform: uppercase;
        }
        tr:hover {
            background: #f8f9fa;
        }
        a {
            color: #3498db;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .icon {
            margin-right: 8px;
        }
        .dir { color: #f39c12; }
        .file { color: #7f8c8d; }
        .size, .date {
            color: #999;
            font-size: 0.9em;
        }
        .parent {
            background: #f8f9fa;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Index of {{.Path}}</h1>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Last Modified</th>
                </tr>
            </thead>
            <tbody>
                {{if ne .Path "/"}}
                <tr class="parent">
                    <td></span><a href="{{.ParentPath}}">..</a></td>
                    <td class="size">-</td>
                    <td class="date">-</td>
                </tr>
                {{end}}
                {{range .Entries}}
                <tr>
                    <td>
                        {{if .IsDir}}
                        <a href="{{$.Path}}{{if ne $.Path "/"}}{{end}}{{.Name}}/">{{.Name}}/</a>
                        {{else}}
                        <a href="{{$.Path}}{{if ne $.Path "/"}}{{end}}{{.Name}}">{{.Name}}</a>
                        {{end}}
                    </td>
                    <td class="size">{{if .IsDir}}-{{else}}{{.Size | formatSize}}{{end}}</td>
                    <td class="date">{{.ModTime.Format "2006-01-02 15:04:05"}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>`

func NewHTTPServer(store *storage.Storage) *HTTPServer {
	return &HTTPServer{
		storage: store,
	}
}

func (s *HTTPServer) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	logger.Info("HTTP server listening on %s", addr)
	go func() {
		if err := s.server.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("HTTP server error: %v", err)
		}
	}()

	return nil
}

func (s *HTTPServer) Stop() {
	if s.server != nil {
		s.server.Close()
	}
}

func (s *HTTPServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "" {
		path = "/"
	}

	logger.Debug("HTTP request: %s %s", r.Method, path)

	inode, err := s.storage.WalkPath(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if inode.IsDir() {
		s.serveDirectory(w, r, path, inode.Ino)
	} else {
		s.serveFile(w, r, path, inode.Ino)
	}
}

func (s *HTTPServer) serveDirectory(w http.ResponseWriter, r *http.Request, path string, ino uint64) {
	if !strings.HasSuffix(path, "/") {
		http.Redirect(w, r, path+"/", http.StatusMovedPermanently)
		return
	}

	entries, err := s.storage.List(ino)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	var dirEntries []dirEntry
	for _, e := range entries {
		inode, err := s.storage.GetInode(e.Ino)
		if err != nil {
			continue
		}

		dirEntries = append(dirEntries, dirEntry{
			Name:    e.Name,
			IsDir:   inode.IsDir(),
			Size:    int64(inode.Size),
			ModTime: inode.Mtime,
		})
	}

	sort.Slice(dirEntries, func(i, j int) bool {
		if dirEntries[i].IsDir != dirEntries[j].IsDir {
			return dirEntries[i].IsDir
		}
		return dirEntries[i].Name < dirEntries[j].Name
	})

	parentPath := filepath.Dir(strings.TrimSuffix(path, "/"))
	if parentPath == "" || parentPath == "." {
		parentPath = "/"
	}
	if !strings.HasSuffix(parentPath, "/") {
		parentPath += "/"
	}

	funcMap := template.FuncMap{
		"formatSize": formatSize,
	}

	tmpl, err := template.New("index").Funcs(funcMap).Parse(indexTemplate)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Path       string
		ParentPath string
		Entries    []dirEntry
	}{
		Path:       path,
		ParentPath: parentPath,
		Entries:    dirEntries,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

func (s *HTTPServer) serveFile(w http.ResponseWriter, r *http.Request, path string, ino uint64) {
	inode, err := s.storage.GetInode(ino)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	data, err := s.storage.GetFileData(ino)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	ext := filepath.Ext(path)
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Header().Set("Last-Modified", inode.Mtime.UTC().Format(http.TimeFormat))

	if r.Method == http.MethodHead {
		return
	}

	io.WriteString(w, string(data))
}

func formatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
