package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"scannn3d/internal/platform/progress"
	"scannn3d/internal/platform/storage"
)

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeSSEEvent(w http.ResponseWriter, ev progress.ScanEvent) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "id: %d\n", ev.Seq)
	_, _ = w.Write([]byte("event: log\n"))
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n\n"))
}

func parseRole(raw string) (storage.Role, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(storage.RoleAdmin):
		return storage.RoleAdmin, nil
	case string(storage.RoleAnalyst), "analysis":
		return storage.RoleAnalyst, nil
	case string(storage.RoleViewer), "view", "views":
		return storage.RoleViewer, nil
	default:
		return "", fmt.Errorf("role must be admin, analyst or viewer")
	}
}

func parseProjectType(raw string) (storage.ProjectType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(storage.ProjectWeb):
		return storage.ProjectWeb, nil
	case string(storage.ProjectAPI):
		return storage.ProjectAPI, nil
	case string(storage.ProjectBugBounty), "bugbounty":
		return storage.ProjectBugBounty, nil
	case string(storage.ProjectCTF):
		return storage.ProjectCTF, nil
	default:
		return "", fmt.Errorf("project type must be web, api, bug_bounty or ctf")
	}
}

func validatePasswordPolicy(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("new password must have at least 8 characters")
	}
	hasLetter := false
	hasDigit := false
	for _, r := range password {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
		}
		if r >= '0' && r <= '9' {
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return fmt.Errorf("new password must contain at least one letter and one number")
	}
	return nil
}

func EnsureReportBase(path string) {
	_ = os.MkdirAll(path, 0o750)
}

func normalizeOrigin(origin string) string {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return ""
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.Scheme + "://" + u.Host
}

func canonicalRequestOrigin(r *http.Request) string {
	if r == nil || r.Host == "" {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := strings.ToLower(strings.TrimSpace(r.Host))
	if host == "" {
		return ""
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		if (scheme == "http" && p == "80") || (scheme == "https" && p == "443") {
			host = h
		}
	}
	return scheme + "://" + host
}

func (s *Server) isOriginAllowed(r *http.Request) bool {
	origin := normalizeOrigin(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if origin == canonicalRequestOrigin(r) {
		return true
	}
	_, ok := s.corsOrigins[origin]
	return ok
}
