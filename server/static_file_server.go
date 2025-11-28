package server

import (
	"embed"
	"io/fs"
	"net/http"
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
