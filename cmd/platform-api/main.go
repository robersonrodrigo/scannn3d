package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"scannn3d/internal/platform/api"
	"scannn3d/internal/platform/auth"
	"scannn3d/internal/platform/orchestration"
	"scannn3d/internal/platform/pentest"
	"scannn3d/internal/platform/progress"
	"scannn3d/internal/platform/recon"
	"scannn3d/internal/platform/storage"
)

//go:embed web/*
var webFS embed.FS

func main() {
	listen := envOr("PLATFORM_LISTEN", ":8095")
	jwtSecret, err := resolveJWTSecret()
	if err != nil {
		log.Fatal(err)
	}
	reportsDir := envOr("PLATFORM_REPORTS_DIR", "./platform-runs")
	templateDir := envOr("PLATFORM_TEMPLATES_DIR", "./internal/scanners/templates")
	reconCacheDSN := envOr("PLATFORM_RECON_CACHE_DSN", "platform-runs/recon-cache.json")
	pentestMaxConcurrent := envInt("PENTEST_MAX_CONCURRENT_JOBS", 2)
	pentestMaxThreads := envInt("PENTEST_MAX_THREADS", 40)
	corsAllowedOrigins := parseAllowedOrigins(envOr("PLATFORM_CORS_ALLOWED_ORIGINS", ""))

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	adminPassword, err := resolveAdminPassword(logger)
	if err != nil {
		log.Fatal(err)
	}
	dbDSN := os.Getenv("PLATFORM_DB_DSN")
	dbDriver := strings.ToLower(strings.TrimSpace(envOr("PLATFORM_DB_DRIVER", "")))
	var store storage.Store
	if dbDriver == "postgres" || strings.HasPrefix(strings.ToLower(dbDSN), "postgres://") || strings.HasPrefix(strings.ToLower(dbDSN), "postgresql://") {
		if strings.TrimSpace(dbDSN) == "" {
			log.Fatal("PLATFORM_DB_DSN is required when PLATFORM_DB_DRIVER=postgres")
		}
		s, err := storage.NewPostgresStore(dbDSN)
		if err != nil {
			log.Fatal(err)
		}
		store = s
		logger.Info("using_postgres_storage")
	} else if dbDSN != "" || dbDriver == "sqlite" {
		if strings.TrimSpace(dbDSN) == "" {
			dbDSN = "/data/platform-runs/scannn3d.db"
		}
		s, err := storage.NewSQLiteStore(dbDSN)
		if err != nil {
			log.Fatal(err)
		}
		store = s
		logger.Info("using_sqlite_storage", "dsn", dbDSN)
	} else {
		store = storage.NewInMemoryStore()
		logger.Info("using_in_memory_storage")
	}

	broker := progress.NewBroker(1000)
	hash, err := auth.HashPassword(adminPassword)
	if err != nil {
		log.Fatal(err)
	}
	store.SeedAdminIfEmpty(hash)
	if strings.TrimSpace(os.Getenv("PLATFORM_ADMIN_PASSWORD")) != "" {
		if err := syncConfiguredAdminPassword(store, adminPassword, logger); err != nil {
			log.Fatal(err)
		}
	}
	orch := orchestration.New(store, logger, reportsDir, 4, broker)
	reconCache, err := recon.NewCache(reconCacheDSN)
	if err != nil {
		log.Fatal(err)
	}
	reconSvc := recon.NewService(logger, reconCache, 2)
	pentestSvc := pentest.NewService(logger, broker, reportsDir, pentestMaxConcurrent, pentestMaxThreads)
	api.EnsureReportBase(reportsDir)
	srv := api.New(store, orch, pentestSvc, reconSvc, broker, []byte(jwtSecret), reportsDir, templateDir, corsAllowedOrigins)

	mux := http.NewServeMux()
	mux.Handle("/api/", srv.Routes())
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	indexHTML, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		log.Fatal(err)
	}
	serveIndex := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexHTML)
	}
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		serveIndex(w)
	})
	staticFiles := http.FileServer(http.FS(sub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			serveIndex(w)
			return
		}
		staticFiles.ServeHTTP(w, r)
	})

	logger.Info("platform_api_started", "listen", listen)
	if err := http.ListenAndServe(listen, withCORS(mux, corsAllowedOrigins)); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func envInt(key string, def int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

func resolveAdminPassword(logger *slog.Logger) (string, error) {
	adminPassword := os.Getenv("PLATFORM_ADMIN_PASSWORD")
	if adminPassword != "" {
		return adminPassword, nil
	}
	generated, err := generateRandomPassword()
	if err != nil {
		return "", err
	}
	logger.Warn(
		"platform_admin_password_generated",
		"message", "PLATFORM_ADMIN_PASSWORD not set; generated password for initial admin seed",
		"username", "admin",
		"generated_password", generated,
	)
	return generated, nil
}

func generateRandomPassword() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func syncConfiguredAdminPassword(store storage.Store, configuredPassword string, logger *slog.Logger) error {
	admin, ok := store.GetUserByUsername("admin")
	if !ok {
		return nil
	}
	if auth.VerifyPassword(admin.PasswordHash, configuredPassword) {
		return nil
	}
	hash, err := auth.HashPassword(configuredPassword)
	if err != nil {
		return err
	}
	if err := store.UpdateUserPassword(admin.ID, hash); err != nil {
		return err
	}
	logger.Info("platform_admin_password_synchronized", "username", admin.Username)
	return nil
}

func resolveJWTSecret() (string, error) {
	raw := strings.TrimSpace(os.Getenv("PLATFORM_JWT_SECRET"))
	if raw == "" {
		return "", errors.New("PLATFORM_JWT_SECRET is required")
	}
	if raw == "change-me-super-secret" {
		return "", errors.New("PLATFORM_JWT_SECRET cannot use the insecure default value")
	}
	if len(raw) < 32 {
		return "", errors.New("PLATFORM_JWT_SECRET must have at least 32 characters")
	}
	return raw, nil
}

func parseAllowedOrigins(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		origin := strings.TrimSpace(part)
		if origin == "" {
			continue
		}
		u, err := url.Parse(origin)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		v := u.Scheme + "://" + u.Host
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
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
	if h, p, err := net.SplitHostPort(host); err == nil {
		if (scheme == "http" && p == "80") || (scheme == "https" && p == "443") {
			host = h
		}
	}
	return scheme + "://" + host
}

func withCORS(next http.Handler, allowedOrigins []string) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowed[origin] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		originAllowed := false
		if origin == "" {
			originAllowed = true
		} else if origin == canonicalRequestOrigin(r) {
			originAllowed = true
		} else {
			_, originAllowed = allowed[origin]
		}

		if !originAllowed {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if origin != "" {
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
