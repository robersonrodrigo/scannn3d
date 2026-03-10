package api

import (
	"net/http"

	"scannn3d/internal/platform/orchestration"
	"scannn3d/internal/platform/pentest"
	"scannn3d/internal/platform/progress"
	"scannn3d/internal/platform/recon"
	"scannn3d/internal/platform/storage"
)

type Server struct {
	store       storage.Store
	orch        *orchestration.Service
	pentest     *pentest.Service
	recon       *recon.Service
	progress    *progress.Broker
	secret      []byte
	reportsBase string
	templateDir string
	corsOrigins map[string]struct{}
}

func New(store storage.Store, orch *orchestration.Service, pentestSvc *pentest.Service, reconSvc *recon.Service, broker *progress.Broker, jwtSecret []byte, reportsBase string, templateDir string, corsAllowedOrigins []string) *Server {
	origins := make(map[string]struct{}, len(corsAllowedOrigins))
	for _, origin := range corsAllowedOrigins {
		if origin == "" {
			continue
		}
		origins[origin] = struct{}{}
	}
	return &Server{
		store:       store,
		orch:        orch,
		pentest:     pentestSvc,
		recon:       reconSvc,
		progress:    broker,
		secret:      jwtSecret,
		reportsBase: reportsBase,
		templateDir: templateDir,
		corsOrigins: origins,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Auth
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("/api/v1/auth/refresh", s.handleRefresh)
	mux.HandleFunc("/api/v1/auth/me", s.auth(s.handleMe))
	mux.HandleFunc("/api/v1/auth/change-password", s.auth(s.handleChangePassword))

	// Users & Admin
	mux.HandleFunc("/api/v1/users", s.auth(s.handleUsers))
	mux.HandleFunc("/api/v1/admin/tools", s.auth(s.handleAdminTools))

	// Projects
	mux.HandleFunc("/api/v1/projects", s.auth(s.handleProjects))
	mux.HandleFunc("/api/v1/projects/", s.auth(s.handleProjectByID))

	// Templates
	mux.HandleFunc("/api/v1/templates", s.auth(s.handleTemplates))
	mux.HandleFunc("/api/v1/templates/", s.auth(s.handleTemplateByID))

	// Recon (Handled in recon_handlers.go)
	mux.HandleFunc("/api/v1/recon/jobs", s.auth(s.handleReconJobs))
	mux.HandleFunc("/api/v1/recon/jobs/", s.auth(s.handleReconJobByID))

	// Pentest (Handled in pentest_handlers.go)
	mux.HandleFunc("/api/v1/pentest/jobs", s.auth(s.handlePentestJobs))
	mux.HandleFunc("/api/v1/pentest/jobs/", s.auth(s.handlePentestJobByID))
	mux.HandleFunc("/api/v1/pentest/ws/", s.handlePentestJobWS)

	// Scans
	mux.HandleFunc("/api/v1/scans/preflight", s.auth(s.handleScansPreflight))
	mux.HandleFunc("/api/v1/scans", s.auth(s.handleScans))
	mux.HandleFunc("/api/v1/scans/", s.auth(s.handleScanByID))

	// Assets & Vulns
	mux.HandleFunc("/api/v1/targets", s.auth(s.handleTargets))
	mux.HandleFunc("/api/v1/targets/", s.auth(s.handleTargetByID))
	mux.HandleFunc("/api/v1/vulnerabilities", s.auth(s.handleVulns))
	mux.HandleFunc("/api/v1/graphs/targets/", s.auth(s.handleGraphByTarget))
	mux.HandleFunc("/api/v1/chains/targets/", s.auth(s.handleChainByTarget))

	// Reports
	mux.HandleFunc("/api/v1/reports/scans/", s.auth(s.handleReportDownload))

	return mux
}
