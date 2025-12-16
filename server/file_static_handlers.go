package server

import (
	"embed"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
)

//go:embed static/*
var staticFiles embed.FS

func FileServerHandler() http.Handler {
	// Create the sub filesystem once
	// Create the file server once
	return http.FileServer(http.FS(StaticFilesFS()))
}

func StaticFilesFS() fs.FS {
	// Create the sub filesystem once
	subFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic("Failed to create sub filesystem: " + err.Error())
	}

	return subFS
}

func StreamFile(w http.ResponseWriter, _ *http.Request, fileName string) error {
	fsys := StaticFilesFS()
	data, err := fs.ReadFile(fsys, fileName)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", fileName, err)
	}

	ext := strings.ToLower(filepath.Ext(fileName))
	ctype := mime.TypeByExtension(ext)
	if ctype == "" {
		// Fallback for unknown extensions
		ctype = http.DetectContentType(data)
	}
	// Ensure UTF-8 for text types when not present
	if strings.HasPrefix(ctype, "text/") && !strings.Contains(strings.ToLower(ctype), "charset=") {
		ctype += "; charset=utf-8"
	}
	w.Header().Set("Content-Type", ctype)
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write %s content: %w", fileName, err)
	}
	return nil
}
