package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	platformauth "scannn3d/internal/platform/auth"
	"scannn3d/internal/platform/storage"
)

func newAdminTestServer(t *testing.T) (*Server, *storage.InMemoryStore, storage.User, storage.User, []byte) {
	t.Helper()

	store := storage.NewInMemoryStore()
	adminHash, err := platformauth.HashPassword("Admin1234")
	if err != nil {
		t.Fatalf("hash admin password: %v", err)
	}
	admin, err := store.CreateUser("admin", adminHash, storage.RoleAdmin)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	userHash, err := platformauth.HashPassword("Viewer123")
	if err != nil {
		t.Fatalf("hash user password: %v", err)
	}
	target, err := store.CreateUser("viewer1", userHash, storage.RoleViewer)
	if err != nil {
		t.Fatalf("create target user: %v", err)
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	srv := New(store, nil, nil, nil, nil, secret, "", "", nil)
	return srv, store, admin, target, secret
}

func accessTokenFor(t *testing.T, secret []byte, user storage.User) string {
	t.Helper()
	token, err := platformauth.IssueAccessToken(secret, user.ID, user.Role, time.Hour)
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	return token
}

func TestHandleUserByIDAdminCanUpdateOtherUser(t *testing.T) {
	srv, store, admin, target, secret := newAdminTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/"+target.ID, strings.NewReader(`{
		"username":"analyst-one",
		"role":"analyst",
		"new_password":"Analyst123",
		"confirm_password":"Analyst123"
	}`))
	req.Header.Set("Authorization", "Bearer "+accessTokenFor(t, secret, admin))
	rec := httptest.NewRecorder()

	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	updated, ok := store.GetUser(target.ID)
	if !ok {
		t.Fatalf("expected updated user to exist")
	}
	if updated.Username != "analyst-one" {
		t.Fatalf("expected updated username, got %q", updated.Username)
	}
	if updated.Role != storage.RoleAnalyst {
		t.Fatalf("expected role analyst, got %q", updated.Role)
	}
	if !platformauth.VerifyPassword(updated.PasswordHash, "Analyst123") {
		t.Fatalf("expected password to be updated")
	}
	if _, ok := store.GetUserByUsername("viewer1"); ok {
		t.Fatalf("expected old username mapping to be removed")
	}
	if renamed, ok := store.GetUserByUsername("analyst-one"); !ok || renamed.ID != target.ID {
		t.Fatalf("expected new username mapping to point to updated user")
	}
}

func TestHandleUserByIDRejectsCurrentAdmin(t *testing.T) {
	srv, _, admin, _, secret := newAdminTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/"+admin.ID, strings.NewReader(`{
		"username":"admin",
		"role":"admin",
		"new_password":"Another123",
		"confirm_password":"Another123"
	}`))
	req.Header.Set("Authorization", "Bearer "+accessTokenFor(t, secret, admin))
	rec := httptest.NewRecorder()

	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleUserByIDRequiresAdmin(t *testing.T) {
	srv, store, _, target, secret := newAdminTestServer(t)

	viewerHash, err := platformauth.HashPassword("Viewer999")
	if err != nil {
		t.Fatalf("hash viewer password: %v", err)
	}
	viewer, err := store.CreateUser("viewer2", viewerHash, storage.RoleViewer)
	if err != nil {
		t.Fatalf("create viewer user: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/"+target.ID, strings.NewReader(`{
		"username":"viewer1",
		"role":"viewer"
	}`))
	req.Header.Set("Authorization", "Bearer "+accessTokenFor(t, secret, viewer))
	rec := httptest.NewRecorder()

	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}
