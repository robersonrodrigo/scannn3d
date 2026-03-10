package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"scannn3d/internal/config"
	"scannn3d/internal/logging"
	"scannn3d/internal/orchestrator"
	"scannn3d/internal/report"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	fmt.Fprintln(os.Stderr, "[DEPRECATED] scannn3d CLI is legacy. Use platform-cli for the unified platform.")
	cfg := &config.Config{}
	var headerFlags stringList
	var modules, endpoints, scopeHosts string

	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.StringVar(&cfg.Target, "target", "", "Base target URL (required)")
	fs.StringVar(&cfg.Method, "method", "GET", "HTTP method")
	fs.StringVar(&cfg.Body, "data", "", "Request body")
	fs.Var(&headerFlags, "header", "Header in key:value format (repeatable)")
	fs.StringVar(&modules, "modules", "all", "Comma-separated modules: all,passive,sqli,xss,ssrf,jwt,bola")
	fs.StringVar(&cfg.OutputDir, "output", "./out", "Output directory")
	externalTools := "all"
	fs.StringVar(&externalTools, "external-tools", "all", "Comma-separated external tools: all,dirsearch,owasp-zap,wapiti,sqlmap,wpscan,nmap,metasploit,nikto,arachni,vega")
	fs.DurationVar(&cfg.ExternalTimeout, "external-timeout", 8*time.Minute, "Timeout per external tool")
	fs.BoolVar(&cfg.DirsearchEnabled, "dirsearch-enabled", true, "Enable dirsearch integration")
	fs.StringVar(&cfg.DirsearchProfile, "dirsearch-profile", "auto", "Dirsearch profile: auto|generic-web|api-rest|spa|wordpress|drupal|joomla|laravel|django|rails|node-express")
	fs.StringVar(&cfg.DirsearchIntensity, "dirsearch-intensity", "balanced", "Dirsearch intensity: conservative|balanced|aggressive")
	fs.StringVar(&endpoints, "endpoints", "/", "Comma-separated endpoints, e.g. /users,/orders?id=1")
	fs.StringVar(&cfg.OpenAPIFile, "openapi", "", "OpenAPI JSON file for endpoint discovery")
	fs.StringVar(&cfg.PostmanFile, "postman", "", "Postman collection JSON file for endpoint discovery")
	fs.BoolVar(&cfg.Crawl, "crawl", false, "Enable crawler-based endpoint discovery")
	fs.IntVar(&cfg.CrawlDepth, "crawl-depth", 1, "Crawler depth (0 = only seeds)")
	fs.IntVar(&cfg.Rate, "rate", 10, "Requests per second")
	fs.IntVar(&cfg.Burst, "burst", 10, "Rate limiter burst")
	fs.IntVar(&cfg.Concurrency, "concurrency", 8, "Concurrent scan workers")
	fs.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "HTTP timeout")
	fs.BoolVar(&cfg.InsecureTLS, "insecure", false, "Skip TLS certificate verification")
	fs.StringVar(&cfg.Format, "format", "both", "Report format: json|html|both")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "Verbose structured logging")
	fs.StringVar(&scopeHosts, "scope-hosts", "", "Comma-separated scope allowlist hosts")

	authType := string(config.AuthNone)
	fs.StringVar(&authType, "auth-type", string(config.AuthNone), "Auth type: none|bearer|basic|apikey")
	fs.StringVar(&cfg.Auth.Token, "auth-token", "", "Bearer token")
	fs.StringVar(&cfg.Auth.Username, "auth-user", "", "Basic auth username")
	fs.StringVar(&cfg.Auth.Password, "auth-pass", "", "Basic auth password")
	fs.StringVar(&cfg.Auth.APIKey, "auth-apikey", "", "API key value")
	fs.StringVar(&cfg.Auth.APIHeader, "auth-apiheader", "X-API-Key", "API key header name")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s --target https://api.example.com [options]\n\n", os.Args[0])
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	cfg.Auth.Type = config.AuthType(strings.ToLower(authType))

	printEthicalBanner()
	if err := normalizeConfig(cfg, headerFlags, modules, endpoints, scopeHosts, externalTools); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func normalizeConfig(cfg *config.Config, headers []string, modules, endpoints, scopeHosts, externalTools string) error {
	cfg.Headers = map[string]string{}
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid header format: %q", h)
		}
		cfg.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	cfg.Modules = splitCSV(modules)
	cfg.Endpoints = splitCSV(endpoints)
	cfg.ScopeHosts = splitCSV(scopeHosts)
	cfg.ExternalTools = splitCSV(externalTools)
	return config.ValidateAndDefault(cfg)
}

func run(cfg *config.Config) error {
	logger, cleanup, err := logging.New(cfg.OutputDir, cfg.Verbose)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx := context.Background()
	start := time.Now()
	result, err := orchestrator.Execute(ctx, cfg, logger)
	if err != nil {
		return err
	}
	rep := result.Report
	rep.Summary.ElapsedMilli = time.Since(start).Milliseconds()
	if err := saveReports(cfg, rep, logger); err != nil {
		return err
	}

	if len(result.ExternalResults) > 0 {
		for _, r := range result.ExternalResults {
			logger.Info("external_tool_status", "tool", r.Tool, "status", r.Status, "artifact", r.Artifact, "elapsed_ms", r.ElapsedMS)
		}
	}

	logger.Info("scan_completed", "findings", len(rep.Findings), "elapsed_ms", rep.Summary.ElapsedMilli)
	fmt.Printf("Findings: %d\n", len(rep.Findings))
	return nil
}

func saveReports(cfg *config.Config, rep report.Report, logger *slog.Logger) error {
	switch strings.ToLower(cfg.Format) {
	case "json":
		p, err := report.SaveJSON(cfg.OutputDir, rep)
		if err != nil {
			return err
		}
		logger.Info("report_written", "format", "json", "path", p)
	case "html":
		p, err := report.SaveHTML(cfg.OutputDir, rep)
		if err != nil {
			return err
		}
		logger.Info("report_written", "format", "html", "path", p)
	case "both":
		jp, err := report.SaveJSON(cfg.OutputDir, rep)
		if err != nil {
			return err
		}
		hp, err := report.SaveHTML(cfg.OutputDir, rep)
		if err != nil {
			return err
		}
		logger.Info("report_written", "format", "json", "path", jp)
		logger.Info("report_written", "format", "html", "path", hp)
	default:
		return fmt.Errorf("unsupported report format: %s", cfg.Format)
	}
	return nil
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func printEthicalBanner() {
	fmt.Println("[ETHICAL USE REQUIRED] This tool is authorized testing only.")
	fmt.Println("You must have explicit written permission before scanning any target.")
	fmt.Println("Unauthorized testing may violate laws and contracts.")
	fmt.Println()
}
