package api

import (
	"net/http"
	"strings"

	"scannn3d/internal/platform/storage"
)

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request, _ storage.User) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.store.ListVulnerabilities())
}

func (s *Server) handleGraphByTarget(w http.ResponseWriter, r *http.Request, _ storage.User) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/graphs/targets/")
	for _, sc := range s.store.ListScans() {
		if sc.TargetID != id {
			continue
		}
		bundle, ok := s.store.BuildScanBundle(sc.ID)
		if ok {
			writeJSON(w, http.StatusOK, map[string]any{"scan_id": sc.ID, "nodes": bundle.GraphNodes, "edges": bundle.GraphEdges})
			return
		}
	}
	writeErr(w, http.StatusNotFound, "graph not found")
}

func (s *Server) handleChainByTarget(w http.ResponseWriter, r *http.Request, _ storage.User) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/chains/targets/")
	for _, sc := range s.store.ListScans() {
		if sc.TargetID != id {
			continue
		}
		bundle, ok := s.store.BuildScanBundle(sc.ID)
		if ok {
			writeJSON(w, http.StatusOK, bundle.AttackChain)
			return
		}
	}
	writeErr(w, http.StatusNotFound, "chain not found")
}
