package api

import (
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"scannn3d/internal/platform/storage"
)

var scanIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func (s *Server) handleReportDownload(w http.ResponseWriter, r *http.Request, _ storage.User) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/reports/scans/")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "missing report path")
		return
	}
	if strings.HasSuffix(path, ".json") {
		scanID := strings.TrimSpace(strings.TrimSuffix(path, ".json"))
		if !scanIDPattern.MatchString(scanID) {
			writeErr(w, http.StatusBadRequest, "invalid scan id")
			return
		}
		http.ServeFile(w, r, filepath.Join(s.reportsBase, scanID, "platform-report.json"))
		return
	}
	if strings.HasSuffix(path, ".html") {
		scanID := strings.TrimSpace(strings.TrimSuffix(path, ".html"))
		if !scanIDPattern.MatchString(scanID) {
			writeErr(w, http.StatusBadRequest, "invalid scan id")
			return
		}
		http.ServeFile(w, r, filepath.Join(s.reportsBase, scanID, "platform-report.html"))
		return
	}
	writeErr(w, http.StatusBadRequest, "unsupported report format")
}
