package auth

import (
	"testing"
	"time"

	"scannn3d/internal/platform/storage"
)

func TestValidatePasswordPolicy(t *testing.T) {
	t.Parallel()

	if err := ValidatePasswordPolicy("StrongPass123"); err != nil {
		t.Fatalf("expected valid password, got %v", err)
	}
	if err := ValidatePasswordPolicy("short1"); err == nil {
		t.Fatalf("expected short password to be rejected")
	}
	if err := ValidatePasswordPolicy("allletters"); err == nil {
		t.Fatalf("expected password without digits to be rejected")
	}
	if err := ValidatePasswordPolicy("12345678"); err == nil {
		t.Fatalf("expected password without letters to be rejected")
	}
}

func TestParseTokenOfType(t *testing.T) {
	t.Parallel()

	secret := []byte("0123456789abcdef0123456789abcdef")

	access, err := IssueAccessToken(secret, "usr-1", storage.RoleAdmin, time.Minute)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	refresh, err := IssueRefreshToken(secret, "usr-1", storage.RoleAdmin, time.Minute)
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}

	if _, err := ParseTokenOfType(secret, access, TokenTypeAccess); err != nil {
		t.Fatalf("expected access token to validate: %v", err)
	}
	if _, err := ParseTokenOfType(secret, refresh, TokenTypeRefresh); err != nil {
		t.Fatalf("expected refresh token to validate: %v", err)
	}
	if _, err := ParseTokenOfType(secret, access, TokenTypeRefresh); err == nil {
		t.Fatalf("expected access token to be rejected as refresh token")
	}
}
