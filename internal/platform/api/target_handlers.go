package api

import (
	"net/http"
	"strings"

	"scannn3d/internal/platform/storage"
)

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request, _ storage.User) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.store.ListTargets())
}

func (s *Server) handleTargetByID(w http.ResponseWriter, r *http.Request, _ storage.User) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/targets/")
	t, ok := s.store.GetTarget(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "target not found")
		return
	}
	latest := storage.Scan{}
	for _, sc := range s.store.ListScans() {
		if sc.TargetID == id {
			latest = sc
			break
		}
	}
	if latest.ID == "" {
		writeJSON(w, http.StatusOK, map[string]any{"target": t})
		return
	}
	bundle, _ := s.store.BuildScanBundle(latest.ID)
	writeJSON(w, http.StatusOK, map[string]any{"target": t, "latest_scan": bundle})
}
