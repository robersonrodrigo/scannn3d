package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"scannn3d/internal/platform/auth"
	"scannn3d/internal/platform/storage"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	u, ok := s.store.GetUserByUsername(strings.TrimSpace(req.Username))
	if !ok || !auth.VerifyPassword(u.PasswordHash, req.Password) {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	access, _ := auth.IssueToken(s.secret, u.ID, u.Role, 20*time.Minute)
	refresh, _ := auth.IssueToken(s.secret, u.ID, u.Role, 24*time.Hour)
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "refresh_token": refresh, "user": u})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	claims, err := auth.ParseToken(s.secret, req.RefreshToken)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	u, ok := s.store.GetUser(claims.Sub)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "user not found")
		return
	}
	access, _ := auth.IssueToken(s.secret, u.ID, u.Role, 20*time.Minute)
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, user storage.User) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, user storage.User) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	currentPassword := strings.TrimSpace(req.CurrentPassword)
	newPassword := strings.TrimSpace(req.NewPassword)
	confirmPassword := strings.TrimSpace(req.ConfirmPassword)
	if currentPassword == "" || newPassword == "" || confirmPassword == "" {
		writeErr(w, http.StatusBadRequest, "current_password, new_password and confirm_password are required")
		return
	}
	if !auth.VerifyPassword(user.PasswordHash, currentPassword) {
		writeErr(w, http.StatusUnauthorized, "invalid current password")
		return
	}
	if newPassword != confirmPassword {
		writeErr(w, http.StatusBadRequest, "new password and confirmation do not match")
		return
	}
	if newPassword == currentPassword {
		writeErr(w, http.StatusBadRequest, "new password must differ from current password")
		return
	}
	if err := validatePasswordPolicy(newPassword); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	if err := s.store.UpdateUserPassword(user.ID, hash); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to update password")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "password changed successfully"})
}

func (s *Server) auth(next func(http.ResponseWriter, *http.Request, storage.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, status, msg := s.authenticate(r)
		if msg != "" {
			writeErr(w, status, msg)
			return
		}
		next(w, r, u)
	}
}

func (s *Server) authenticate(r *http.Request) (storage.User, int, string) {
	tokenRaw, err := auth.BearerToken(r.Header.Get("Authorization"))
	if err != nil {
		return storage.User{}, http.StatusUnauthorized, "missing bearer token"
	}
	claims, err := auth.ParseToken(s.secret, tokenRaw)
	if err != nil {
		return storage.User{}, http.StatusUnauthorized, "invalid token"
	}
	u, ok := s.store.GetUser(claims.Sub)
	if !ok {
		return storage.User{}, http.StatusUnauthorized, "user not found"
	}
	return u, 0, ""
}
