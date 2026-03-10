package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"scannn3d/internal/config"
	"scannn3d/internal/exttools"
	"scannn3d/internal/logging"
	"scannn3d/internal/orchestrator"
	"scannn3d/internal/report"
)

//go:embed static/*
var staticFS embed.FS

type ScanRequest struct {
	Target             string            `json:"target"`
	Endpoints          []string          `json:"endpoints"`
	OpenAPIFile        string            `json:"openapi_file"`
	PostmanFile        string            `json:"postman_file"`
	Crawl              bool              `json:"crawl"`
	CrawlDepth         int               `json:"crawl_depth"`
	Method             string            `json:"method"`
	Body               string            `json:"body"`
	Headers            map[string]string `json:"headers"`
	Rate               int               `json:"rate"`
	Burst              int               `json:"burst"`
	Concurrency        int               `json:"concurrency"`
	TimeoutMS          int               `json:"timeout_ms"`
	InsecureTLS        bool              `json:"insecure_tls"`
	ScopeHosts         []string          `json:"scope_hosts"`
	Modules            []string          `json:"modules"`
	ExternalTools      []string          `json:"external_tools"`
	DirsearchProfile   string            `json:"dirsearch_profile"`
	DirsearchIntensity string            `json:"dirsearch_intensity"`
	DirsearchEnabled   bool              `json:"dirsearch_enabled"`
	Format             string            `json:"format"`
	AuthType           string            `json:"auth_type"`
	AuthToken          string            `json:"auth_token"`
	AuthUser           string            `json:"auth_user"`
	AuthPass           string            `json:"auth_pass"`
	AuthAPIKey         string            `json:"auth_apikey"`
	AuthAPIHdr         string            `json:"auth_apiheader"`
	Verbose            bool              `json:"verbose"`
}

type Job struct {
	ID              string           `json:"id"`
	Status          string           `json:"status"`
	Phase           string           `json:"phase,omitempty"`
	Progress        int              `json:"progress"`
	Error           string           `json:"error,omitempty"`
	StartedAt       time.Time        `json:"started_at"`
	FinishedAt      *time.Time       `json:"finished_at,omitempty"`
	OutputDir       string           `json:"output_dir"`
	Config          config.Config    `json:"config"`
	Report          *report.Report   `json:"report,omitempty"`
	ExternalResults []extools.Result `json:"external_results,omitempty"`
	JSONPath        string           `json:"json_path,omitempty"`
	HTMLPath        string           `json:"html_path,omitempty"`
	AuditPath       string           `json:"audit_path,omitempty"`
}

type Server struct {
	baseOutput string
	verbose    bool

	seq  atomic.Uint64
	mu   sync.RWMutex
	jobs map[string]*Job
}

func main() {
	fmt.Fprintln(os.Stderr, "[DEPRECATED] scannn3d-ui is legacy. Use platform-api on port 8095.")
	listen := flag.String("listen", ":8088", "HTTP listen address")
	output := flag.String("output", "./ui-runs", "Base output directory for scan artifacts")
	verbose := flag.Bool("verbose", false, "Enable verbose server logs")
	flag.Parse()

	if err := os.MkdirAll(*output, 0o750); err != nil {
		log.Fatalf("create output dir: %v", err)
	}

	s := &Server{baseOutput: *output, verbose: *verbose, jobs: map[string]*Job{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", s.handleCreateScan)
	mux.HandleFunc("/api/jobs", s.handleListJobs)
	mux.HandleFunc("/api/jobs/", s.handleJob)
	mux.HandleFunc("/api/schema", s.handleSchema)

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("static fs: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	fmt.Println("[ETHICAL USE REQUIRED] Authorized testing only.")
	fmt.Printf("scannn3d-ui listening on %s\n", *listen)
	if err := http.ListenAndServe(*listen, withCORS(mux)); err != nil {
		log.Fatal(err)
	}
}

func (s *Server) handleSchema(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"modules":               []string{"passive", "sqli", "xss", "ssrf", "jwt", "bola"},
		"external_tools":        []string{"dirsearch", "owasp-zap", "wapiti", "sqlmap", "wpscan", "nmap", "metasploit", "nikto", "arachni", "vega"},
		"dirsearch_profiles":    []string{"auto", "generic-web", "api-rest", "spa", "wordpress", "drupal", "joomla", "laravel", "django", "rails", "node-express"},
		"dirsearch_intensities": []string{"conservative", "balanced", "aggressive"},
		"auth_types":            []string{"none", "bearer", "basic", "apikey"},
		"formats":               []string{"json", "html", "both"},
	})
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}

	cfg := toConfig(req)
	if err := config.ValidateAndDefault(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(cfg.Modules) == 0 {
		cfg.Modules = []string{"all"}
	}
	if len(cfg.ExternalTools) == 0 {
		cfg.ExternalTools = []string{"all"}
	}

	id := s.nextID()
	outDir := filepath.Join(s.baseOutput, id)
	job := &Job{ID: id, Status: "queued", Phase: "queued", Progress: 0, StartedAt: time.Now().UTC(), OutputDir: outDir, Config: cfg}

	s.mu.Lock()
	s.jobs[id] = job
	s.mu.Unlock()

	go s.runJob(job)
	writeJSON(w, http.StatusAccepted, map[string]any{"id": id, "status": job.Status})
}

func (s *Server) runJob(job *Job) {
	s.setStatus(job.ID, "running", "starting", 2, "")
	if err := os.MkdirAll(job.OutputDir, 0o750); err != nil {
		s.setStatus(job.ID, "failed", "failed", job.Progress, err.Error())
		return
	}

	logger, cleanup, err := logging.New(job.OutputDir, s.verbose || job.Config.Verbose)
	if err != nil {
		s.setStatus(job.ID, "failed", "failed", job.Progress, err.Error())
		return
	}
	defer cleanup()

	ctx := context.Background()
	job.Config.OutputDir = job.OutputDir
	result, err := orchestrator.ExecuteWithHooks(ctx, &job.Config, logger, orchestrator.Hooks{
		PhaseHook: func(phase string, progress int) {
			s.setStatus(job.ID, "running", phase, progress, "")
		},
		ExternalStatusHook: func(r extools.Result) {
			s.upsertExternalResult(job.ID, r)
		},
	})
	if err != nil && isTLSUnknownAuthorityErr(err) && !job.Config.InsecureTLS {
		logger.Warn("tls_unknown_authority_retry_insecure", "target", job.Config.Target)
		s.setStatus(job.ID, "running", "retry_insecure_tls", 30, "")
		job.Config.InsecureTLS = true
		result, err = orchestrator.ExecuteWithHooks(ctx, &job.Config, logger, orchestrator.Hooks{
			PhaseHook: func(phase string, progress int) {
				s.setStatus(job.ID, "running", phase, progress, "")
			},
			ExternalStatusHook: func(r extools.Result) {
				s.upsertExternalResult(job.ID, r)
			},
		})
	}
	if err != nil {
		s.setStatus(job.ID, "failed", "failed", job.Progress, err.Error())
		return
	}
	rep := result.Report

	jsonPath, htmlPath, err := saveReportArtifacts(job.Config.Format, job.OutputDir, rep)
	if err != nil {
		s.setStatus(job.ID, "failed", "failed", job.Progress, err.Error())
		return
	}

	now := time.Now().UTC()
	s.mu.Lock()
	job.Status = "completed"
	job.Phase = "completed"
	job.Progress = 100
	job.FinishedAt = &now
	job.Report = &rep
	job.ExternalResults = result.ExternalResults
	job.JSONPath = jsonPath
	job.HTMLPath = htmlPath
	job.AuditPath = filepath.Join(job.OutputDir, "audit.log")
	s.mu.Unlock()
}

func saveReportArtifacts(format string, outDir string, rep report.Report) (string, string, error) {
	var jsonPath, htmlPath string
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "both"
	}
	switch format {
	case "json":
		p, err := report.SaveJSON(outDir, rep)
		return p, "", err
	case "html":
		p, err := report.SaveHTML(outDir, rep)
		return "", p, err
	case "both":
		jp, err := report.SaveJSON(outDir, rep)
		if err != nil {
			return "", "", err
		}
		hp, err := report.SaveHTML(outDir, rep)
		if err != nil {
			return "", "", err
		}
		jsonPath = jp
		htmlPath = hp
	default:
		return "", "", fmt.Errorf("unsupported report format: %s", format)
	}
	return jsonPath, htmlPath, nil
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.mu.RLock()
	list := make([]*Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		list = append(list, j)
	}
	s.mu.RUnlock()
	sort.Slice(list, func(i, j int) bool { return list[i].StartedAt.After(list[j].StartedAt) })
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "missing job id")
		return
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	id := parts[0]

	s.mu.RLock()
	job, ok := s.jobs[id]
	s.mu.RUnlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}

	if len(parts) > 1 && parts[1] == "report" {
		if job.Report == nil {
			writeErr(w, http.StatusNotFound, "report not ready")
			return
		}
		writeJSON(w, http.StatusOK, job.Report)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) nextID() string {
	n := s.seq.Add(1)
	return fmt.Sprintf("scan-%d-%d", time.Now().Unix(), n)
}

func (s *Server) setStatus(id string, status string, phase string, progress int, errMsg string) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return
	}
	job.Status = status
	if strings.TrimSpace(phase) != "" {
		job.Phase = phase
	}
	if progress > 0 {
		job.Progress = progress
	}
	job.Error = errMsg
	if status == "failed" || status == "completed" {
		job.FinishedAt = &now
	}
}

func (s *Server) upsertExternalResult(id string, r extools.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return
	}
	for i := range job.ExternalResults {
		if job.ExternalResults[i].Tool == r.Tool {
			job.ExternalResults[i] = r
			return
		}
	}
	job.ExternalResults = append(job.ExternalResults, r)
}

func toConfig(req ScanRequest) config.Config {
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dirsearchEnabled := req.DirsearchEnabled
	if !dirsearchEnabled {
		for _, t := range req.ExternalTools {
			tt := strings.ToLower(strings.TrimSpace(t))
			if tt == "all" || tt == "dirsearch" {
				dirsearchEnabled = true
				break
			}
		}
	}
	return config.Config{
		Target:             req.Target,
		Endpoints:          req.Endpoints,
		OpenAPIFile:        req.OpenAPIFile,
		PostmanFile:        req.PostmanFile,
		Crawl:              req.Crawl,
		CrawlDepth:         req.CrawlDepth,
		Method:             req.Method,
		Body:               req.Body,
		Headers:            req.Headers,
		Rate:               req.Rate,
		Burst:              req.Burst,
		Concurrency:        req.Concurrency,
		Timeout:            timeout,
		InsecureTLS:        req.InsecureTLS,
		ScopeHosts:         req.ScopeHosts,
		Modules:            req.Modules,
		ExternalTools:      req.ExternalTools,
		DirsearchEnabled:   dirsearchEnabled,
		DirsearchProfile:   req.DirsearchProfile,
		DirsearchIntensity: req.DirsearchIntensity,
		OutputDir:          "",
		Format:             req.Format,
		Verbose:            req.Verbose,
		Auth: config.AuthConfig{
			Type:      config.AuthType(strings.ToLower(req.AuthType)),
			Token:     req.AuthToken,
			Username:  req.AuthUser,
			Password:  req.AuthPass,
			APIKey:    req.AuthAPIKey,
			APIHeader: req.AuthAPIHdr,
		},
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isTLSUnknownAuthorityErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "certificate signed by unknown authority")
}
