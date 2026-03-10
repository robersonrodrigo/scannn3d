package api

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"

	"scannn3d/internal/platform/auth"
	"scannn3d/internal/platform/storage"
)

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, user storage.User) {
	if user.Role != storage.RoleAdmin {
		writeErr(w, http.StatusForbidden, "admin role required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.ListUsers())
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid body")
			return
		}
		username := strings.TrimSpace(req.Username)
		password := strings.TrimSpace(req.Password)
		if username == "" || password == "" {
			writeErr(w, http.StatusBadRequest, "username and password are required")
			return
		}
		if err := auth.ValidatePasswordPolicy(password); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		role, err := parseRole(req.Role)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		created, err := s.store.CreateUser(username, hash, role)
		if err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleUserByID(w http.ResponseWriter, r *http.Request, user storage.User) {
	if user.Role != storage.RoleAdmin {
		writeErr(w, http.StatusForbidden, "admin role required")
		return
	}
	if r.Method != http.MethodPut {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	userID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/users/"))
	if userID == "" {
		writeErr(w, http.StatusBadRequest, "missing user id")
		return
	}
	target, ok := s.store.GetUser(userID)
	if !ok {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if target.ID == user.ID {
		writeErr(w, http.StatusBadRequest, "use account settings to manage your own account")
		return
	}

	var req struct {
		Username        string `json:"username"`
		Role            string `json:"role"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		writeErr(w, http.StatusBadRequest, "username is required")
		return
	}
	role, err := parseRole(req.Role)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	newPassword := strings.TrimSpace(req.NewPassword)
	confirmPassword := strings.TrimSpace(req.ConfirmPassword)
	if (newPassword == "") != (confirmPassword == "") {
		writeErr(w, http.StatusBadRequest, "new_password and confirm_password are required together")
		return
	}

	passwordHash := ""
	if newPassword != "" {
		if newPassword != confirmPassword {
			writeErr(w, http.StatusBadRequest, "new password and confirmation do not match")
			return
		}
		if auth.VerifyPassword(target.PasswordHash, newPassword) {
			writeErr(w, http.StatusBadRequest, "new password must differ from current password")
			return
		}
		if err := auth.ValidatePasswordPolicy(newPassword); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		passwordHash, err = auth.HashPassword(newPassword)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
	}

	updated, err := s.store.UpdateUser(target.ID, username, passwordHash, role)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already exists") {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, "failed to update user")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleAdminTools(w http.ResponseWriter, r *http.Request, user storage.User) {
	if user.Role != storage.RoleAdmin {
		writeErr(w, http.StatusForbidden, "admin role required")
		return
	}
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tools := []string{"subfinder", "cloudlist", "naabu", "katana", "chaos", "uncover", "asnmap", "alterx", "nmap", "ffuf", "nuclei", "sqlmap", "wapiti", "dirsearch", "nikto", "zaproxy", "msfconsole", "wafw00f", "whatweb"}
	type toolStatus struct {
		Name      string `json:"name"`
		Available bool   `json:"available"`
		Path      string `json:"path,omitempty"`
	}
	resp := make([]toolStatus, 0, len(tools))
	for _, name := range tools {
		p, err := exec.LookPath(name)
		if err != nil {
			resp = append(resp, toolStatus{Name: name, Available: false})
			continue
		}
		resp = append(resp, toolStatus{Name: name, Available: true, Path: p})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": resp})
}
