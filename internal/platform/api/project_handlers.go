package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"scannn3d/internal/platform/storage"
)

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request, user storage.User) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.ListProjects())
	case http.MethodPost:
		if user.Role == storage.RoleViewer {
			writeErr(w, http.StatusForbidden, "viewer profile cannot create projects")
			return
		}
		var req struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Scope       []string `json:"scope"`
			Type        string   `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid body")
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			writeErr(w, http.StatusBadRequest, "project name is required")
			return
		}
		if len(req.Scope) == 0 {
			writeErr(w, http.StatusBadRequest, "project scope is required")
			return
		}
		scope := make([]string, 0, len(req.Scope))
		seen := map[string]struct{}{}
		for _, raw := range req.Scope {
			v := strings.TrimSpace(raw)
			if v == "" {
				continue
			}
			key := strings.ToLower(v)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			scope = append(scope, v)
		}
		if len(scope) == 0 {
			writeErr(w, http.StatusBadRequest, "project scope is required")
			return
		}
		typ, err := parseProjectType(req.Type)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		created, err := s.store.CreateProject(name, strings.TrimSpace(req.Description), scope, typ, user.ID)
		if err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleProjectByID(w http.ResponseWriter, r *http.Request, _ storage.User) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/projects/"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing project id")
		return
	}
	p, ok := s.store.GetProject(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "project not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}
