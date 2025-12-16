package server

import (
	"embed"
	"html/template"
	"io/fs"
)

//go:embed templates/*
var templateFiles embed.FS

func TemplateFilesFS() fs.FS {
	// Create the sub filesystem once
	subFS, err := fs.Sub(templateFiles, "templates")
	if err != nil {
		panic("Failed to create templates sub filesystem: " + err.Error())
	}
	return subFS
}

// ParseTemplate parses a template from the embedded filesystem
func ParseTemplate(name string) (*template.Template, error) {
	content, err := fs.ReadFile(TemplateFilesFS(), name)
	if err != nil {
		return nil, err
	}
	return template.New(name).Parse(string(content))
}
