package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"scannn3d/internal/platform/storage"
	"scannn3d/internal/scanners"

	"gopkg.in/yaml.v3"
)

func (s *Server) handleTemplates(w http.ResponseWriter, r *http.Request, user storage.User) {
	switch r.Method {
	case http.MethodGet:
		s.listTemplates(w, r)
	case http.MethodPost:
		if user.Role != storage.RoleAdmin {
			writeErr(w, http.StatusForbidden, "admin role required to upload templates")
			return
		}
		s.uploadTemplate(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listTemplates(w http.ResponseWriter, r *http.Request) {
	if s.templateDir == "" {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	files, err := os.ReadDir(s.templateDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to read templates directory")
		return
	}

	type templateInfo struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Severity string `json:"severity"`
		Path     string `json:"path"`
	}
	res := make([]templateInfo, 0)
	for _, f := range files {
		if f.IsDir() || (!strings.HasSuffix(f.Name(), ".yaml") && !strings.HasSuffix(f.Name(), ".yml")) {
			continue
		}
		path := filepath.Join(s.templateDir, f.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var t scanners.Template
		if err := yaml.Unmarshal(data, &t); err != nil {
			continue
		}
		res = append(res, templateInfo{
			ID:       t.ID,
			Name:     t.Info.Name,
			Severity: t.Info.Severity,
			Path:     f.Name(),
		})
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) uploadTemplate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "failed to parse form")
		return
	}
	file, header, err := r.FormFile("template")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing template file")
		return
	}
	defer file.Close()

	if !strings.HasSuffix(header.Filename, ".yaml") && !strings.HasSuffix(header.Filename, ".yml") {
		writeErr(w, http.StatusBadRequest, "only .yaml or .yml files allowed")
		return
	}

	data, err := io.ReadAll(file)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to read file")
		return
	}

	// Validate YAML
	var t scanners.Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid template YAML: "+err.Error())
		return
	}
	if t.ID == "" {
		writeErr(w, http.StatusBadRequest, "template ID is required")
		return
	}

	if err := os.MkdirAll(s.templateDir, 0o750); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create templates directory")
		return
	}

	dstPath := filepath.Join(s.templateDir, filepath.Base(header.Filename))
	if err := os.WriteFile(dstPath, data, 0o640); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to save template")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"message": "template uploaded successfully", "id": t.ID})
}

func (s *Server) handleTemplateByID(w http.ResponseWriter, r *http.Request, user storage.User) {
	filename := filepath.Base(r.URL.Path)
	if filename == "" || filename == "." || filename == "/" {
		writeErr(w, http.StatusBadRequest, "invalid template path")
		return
	}

	path := filepath.Join(s.templateDir, filename)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		writeErr(w, http.StatusNotFound, "template not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(path)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to read template")
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	case http.MethodDelete:
		if user.Role != storage.RoleAdmin {
			writeErr(w, http.StatusForbidden, "admin role required to delete templates")
			return
		}
		if err := os.Remove(path); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to delete template")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "template deleted"})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
