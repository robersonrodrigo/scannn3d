package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"scannn3d/internal/platform/orchestration"
	"scannn3d/internal/platform/progress"
	"scannn3d/internal/platform/storage"
)

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request, user storage.User) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.ListScans())
	case http.MethodPost:
		if user.Role == storage.RoleViewer {
			writeErr(w, http.StatusForbidden, "viewer profile cannot create scans")
			return
		}
		var req struct {
			Target           string           `json:"target"`
			Mode             storage.ScanMode `json:"mode"`
			TargetType       string           `json:"target_type"`
			IncludeSubfinder bool             `json:"include_subfinder"`
			Profile          string           `json:"profile"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid body")
			return
		}
		target := strings.TrimSpace(req.Target)
		if target == "" {
			writeErr(w, http.StatusBadRequest, "target required")
			return
		}
		scan, err := s.orch.CreateScanWithOptions(target, req.Mode, user.ID, orchestration.ScanOptions{
			TargetType:       req.TargetType,
			IncludeSubfinder: req.IncludeSubfinder,
			Profile:          strings.TrimSpace(req.Profile),
		})
		if err != nil {
			var dupErr *orchestration.DuplicateScanError
			if errors.As(err, &dupErr) {
				writeJSON(w, http.StatusConflict, map[string]any{
					"error":             dupErr.Error(),
					"existing_scan_id":  dupErr.ExistingScanID,
					"normalized_target": dupErr.NormalizedTarget,
					"mode":              dupErr.Mode,
				})
				return
			}
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, scan)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleScansPreflight(w http.ResponseWriter, r *http.Request, user storage.User) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if user.Role == storage.RoleViewer {
		writeErr(w, http.StatusForbidden, "viewer profile cannot create scans")
		return
	}
	var req struct {
		Target           string           `json:"target"`
		Mode             storage.ScanMode `json:"mode"`
		TargetType       string           `json:"target_type"`
		IncludeSubfinder bool             `json:"include_subfinder"`
		Profile          string           `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		writeErr(w, http.StatusBadRequest, "target required")
		return
	}
	preflight, err := s.orch.PreflightScan(target, req.Mode, orchestration.ScanOptions{
		TargetType:       req.TargetType,
		IncludeSubfinder: req.IncludeSubfinder,
		Profile:          strings.TrimSpace(req.Profile),
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	duplicateBlocked := false
	dup := map[string]any{"blocked": false}
	if existing, ok := s.store.FindActiveScanByTargetMode(preflight.NormalizedTarget, preflight.ResolvedMode); ok {
		duplicateBlocked = true
		dup = map[string]any{
			"blocked":          true,
			"existing_scan_id": existing.ID,
			"reason":           "scan with same target and mode already queued/running",
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"normalized_target":    preflight.NormalizedTarget,
		"resolved_target_type": preflight.ResolvedTargetType,
		"resolved_mode":        preflight.ResolvedMode,
		"profile":              preflight.Profile,
		"include_subfinder":    preflight.IncludeSubfinder,
		"execution_plan":       preflight.ExecutionPlan,
		"warnings":             preflight.Warnings,
		"can_submit":           !duplicateBlocked,
		"duplicate":            dup,
	})
}

func (s *Server) handleScanByID(w http.ResponseWriter, r *http.Request, user storage.User) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	if strings.HasSuffix(path, "/events") {
		scanID := strings.TrimSuffix(path, "/events")
		s.handleScanEvents(w, r, user, scanID)
		return
	}
	if strings.HasSuffix(path, "/events/history") {
		scanID := strings.TrimSuffix(path, "/events/history")
		s.handleScanEventsHistory(w, r, user, scanID)
		return
	}

	id := path
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing scan id")
		return
	}
	bundle, ok := s.store.BuildScanBundle(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) handleScanEventsHistory(w http.ResponseWriter, r *http.Request, _ storage.User, scanID string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if scanID == "" {
		writeErr(w, http.StatusBadRequest, "missing scan id")
		return
	}
	if _, ok := s.store.GetScan(scanID); !ok {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}
	var since int64
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
			since = parsed
		}
	}
	if s.progress == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []progress.ScanEvent{}, "last_seq": 0})
		return
	}
	events := s.progress.History(scanID, since)
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "last_seq": s.progress.LastSeq(scanID)})
}

func (s *Server) handleScanEvents(w http.ResponseWriter, r *http.Request, _ storage.User, scanID string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if scanID == "" {
		writeErr(w, http.StatusBadRequest, "missing scan id")
		return
	}
	if _, ok := s.store.GetScan(scanID); !ok {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}
	if s.progress == nil {
		writeErr(w, http.StatusServiceUnavailable, "progress stream unavailable")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "stream unsupported")
		return
	}

	var since int64
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
			since = parsed
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	for _, ev := range s.progress.History(scanID, since) {
		writeSSEEvent(w, ev)
		since = ev.Seq
	}
	flusher.Flush()

	ch, cancel := s.progress.Subscribe(scanID)
	defer cancel()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			if ev.Seq <= since {
				continue
			}
			writeSSEEvent(w, ev)
			flusher.Flush()
			since = ev.Seq
		case <-heartbeat.C:
			_, _ = w.Write([]byte(": heartbeat\n\n"))
			flusher.Flush()
			if sc, ok := s.store.GetScan(scanID); ok && (sc.Status == storage.ScanCompleted || sc.Status == storage.ScanFailed) {
				return
			}
		}
	}
}
