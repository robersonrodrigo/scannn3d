package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"scannn3d/internal/platform/recon"
	"scannn3d/internal/platform/storage"
)

func (s *Server) handleReconJobs(w http.ResponseWriter, r *http.Request, user storage.User) {
	if s.recon == nil {
		writeErr(w, http.StatusServiceUnavailable, "recon service unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.recon.ListJobs())
	case http.MethodPost:
		if user.Role == storage.RoleViewer {
			writeErr(w, http.StatusForbidden, "viewer profile cannot create recon jobs")
			return
		}
		var req recon.ReconInput
		if err := decodeJSON(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid body")
			return
		}
		job, err := s.recon.CreateJob(req, user.ID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, job)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleReconJobByID(w http.ResponseWriter, r *http.Request, user storage.User) {
	if s.recon == nil {
		writeErr(w, http.StatusServiceUnavailable, "recon service unavailable")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/recon/jobs/")
	if strings.HasSuffix(path, "/events") {
		id := strings.TrimSuffix(path, "/events")
		s.handleReconEvents(w, r, user, id)
		return
	}
	if strings.HasSuffix(path, "/events/history") {
		id := strings.TrimSuffix(path, "/events/history")
		s.handleReconEventsHistory(w, r, user, id)
		return
	}
	if strings.HasSuffix(path, "/result") {
		id := strings.TrimSuffix(path, "/result")
		s.handleReconResult(w, r, user, id)
		return
	}
	if strings.HasSuffix(path, "/rerun") {
		id := strings.TrimSuffix(path, "/rerun")
		s.handleReconRerun(w, r, user, id)
		return
	}
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.TrimSpace(path)
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing recon job id")
		return
	}
	job, ok := s.recon.GetJob(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "recon job not found")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleReconResult(w http.ResponseWriter, r *http.Request, _ storage.User, id string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if strings.TrimSpace(id) == "" {
		writeErr(w, http.StatusBadRequest, "missing recon job id")
		return
	}
	result, ok := s.recon.GetResult(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "recon result not found")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleReconRerun(w http.ResponseWriter, r *http.Request, user storage.User, id string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if user.Role == storage.RoleViewer {
		writeErr(w, http.StatusForbidden, "viewer profile cannot rerun recon jobs")
		return
	}
	job, err := s.recon.Rerun(id, user.ID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleReconEventsHistory(w http.ResponseWriter, r *http.Request, _ storage.User, id string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if strings.TrimSpace(id) == "" {
		writeErr(w, http.StatusBadRequest, "missing recon job id")
		return
	}
	if _, ok := s.recon.GetJob(id); !ok {
		writeErr(w, http.StatusNotFound, "recon job not found")
		return
	}
	var since int64
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			since = v
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": s.recon.History(id, since), "last_seq": s.recon.LastSeq(id)})
}

func (s *Server) handleReconEvents(w http.ResponseWriter, r *http.Request, _ storage.User, id string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if strings.TrimSpace(id) == "" {
		writeErr(w, http.StatusBadRequest, "missing recon job id")
		return
	}
	if _, ok := s.recon.GetJob(id); !ok {
		writeErr(w, http.StatusNotFound, "recon job not found")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "stream unsupported")
		return
	}
	var since int64
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			since = v
		}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	for _, ev := range s.recon.History(id, since) {
		writeReconSSEEvent(w, ev)
		since = ev.Seq
	}
	flusher.Flush()

	ch, cancel := s.recon.Subscribe(id)
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
			writeReconSSEEvent(w, ev)
			flusher.Flush()
			since = ev.Seq
		case <-heartbeat.C:
			_, _ = w.Write([]byte(": heartbeat\n\n"))
			flusher.Flush()
			j, _ := s.recon.GetJob(id)
			if j.Status == recon.JobCompleted || j.Status == recon.JobFailed {
				return
			}
		}
	}
}

func writeReconSSEEvent(w http.ResponseWriter, ev recon.Event) {
	b, err := encodeJSON(ev)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "id: %d\n", ev.Seq)
	_, _ = w.Write([]byte("event: log\n"))
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n\n"))
}

func decodeJSON(r *http.Request, out any) error {
	return json.NewDecoder(r.Body).Decode(out)
}

func encodeJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}
