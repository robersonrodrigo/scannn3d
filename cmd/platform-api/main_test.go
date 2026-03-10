package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnvFileDoesNotOverrideExistingValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "PLATFORM_JWT_SECRET=file-secret\nPLATFORM_ADMIN_PASSWORD=StrongPass123\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Setenv("PLATFORM_JWT_SECRET", "existing-secret")
	if err := loadEnvFile(path); err != nil {
		t.Fatalf("loadEnvFile: %v", err)
	}
	if got := os.Getenv("PLATFORM_JWT_SECRET"); got != "existing-secret" {
		t.Fatalf("expected existing env to be preserved, got %q", got)
	}
	if got := os.Getenv("PLATFORM_ADMIN_PASSWORD"); got != "StrongPass123" {
		t.Fatalf("expected file env to be loaded, got %q", got)
	}
}

func TestResolveJWTSecretRejectsPlaceholder(t *testing.T) {
	t.Setenv("PLATFORM_JWT_SECRET", "REPLACE_ME_WITH_A_RANDOM_SECRET_AT_LEAST_32_CHARS")
	if _, err := resolveJWTSecret(); err == nil {
		t.Fatalf("expected placeholder secret to be rejected")
	}
}
