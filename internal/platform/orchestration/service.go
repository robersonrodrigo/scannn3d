package orchestration

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"scannn3d/internal/platform/correlation"
	"scannn3d/internal/platform/infra"
	"scannn3d/internal/platform/progress"
	"scannn3d/internal/platform/report"
	"scannn3d/internal/platform/storage"
	"scannn3d/internal/platform/webscan"
)

type Service struct {
	store     storage.Store
	logger    *slog.Logger
	outputDir string
	workers   chan struct{}
	progress  *progress.Broker
}

type ScanOptions struct {
	TargetType       string
	IncludeSubfinder bool
	Profile          string
}

type ExecutionPlan struct {
	Phases []string `json:"phases"`
	Tools  []string `json:"tools"`
	Notes  []string `json:"notes"`
}

type PreflightResult struct {
	RawTarget          string           `json:"raw_target"`
	NormalizedTarget   string           `json:"normalized_target"`
	ResolvedTargetType string           `json:"resolved_target_type"`
	ResolvedMode       storage.ScanMode `json:"resolved_mode"`
	IncludeSubfinder   bool             `json:"include_subfinder"`
	Profile            string           `json:"profile"`
	ExecutionPlan      ExecutionPlan    `json:"execution_plan"`
	Warnings           []string         `json:"warnings"`
}

type DuplicateScanError struct {
	ExistingScanID   string
	NormalizedTarget string
	Mode             storage.ScanMode
}

func (e *DuplicateScanError) Error() string {
	return "duplicate scan in progress"
}

func New(store storage.Store, logger *slog.Logger, outputDir string, maxConcurrent int, broker *progress.Broker) *Service {
	if maxConcurrent <= 0 {
		maxConcurrent = 4
	}
	if outputDir == "" {
		outputDir = "./platform-runs"
	}
	return &Service{store: store, logger: logger, outputDir: outputDir, workers: make(chan struct{}, maxConcurrent), progress: broker}
}

func (s *Service) CreateScan(targetAddr string, mode storage.ScanMode, userID string) (storage.Scan, error) {
	return s.CreateScanWithOptions(targetAddr, mode, userID, ScanOptions{})
}

func (s *Service) CreateScanWithOptions(targetAddr string, mode storage.ScanMode, userID string, opts ScanOptions) (storage.Scan, error) {
	preflight, err := s.PreflightScan(targetAddr, mode, opts)
	if err != nil {
		s.logger.Warn("platform_scan_request_rejected", "reason", "invalid_target", "mode", mode, "target_raw", targetAddr, "err", err)
		return storage.Scan{}, err
	}
	if existing, ok := s.store.FindActiveScanByTargetMode(preflight.NormalizedTarget, preflight.ResolvedMode); ok {
		return storage.Scan{}, &DuplicateScanError{
			ExistingScanID:   existing.ID,
			NormalizedTarget: preflight.NormalizedTarget,
			Mode:             preflight.ResolvedMode,
		}
	}
	s.logger.Info("platform_scan_request_received",
		"mode", preflight.ResolvedMode,
		"target_raw", targetAddr,
		"target_normalized", preflight.NormalizedTarget,
		"target_type", preflight.ResolvedTargetType,
		"profile", preflight.Profile)

	target := s.store.FindOrCreateTarget(preflight.NormalizedTarget, userID)
	scan := s.store.CreateScan(target.ID, preflight.ResolvedMode, userID, preflight.NormalizedTarget, preflight.ResolvedTargetType, preflight.Profile)
	s.emit(scan.ID, "INFO", "queued", "scan_queued", "Scan enfileirado.", 1, map[string]any{
		"target":            target.Address,
		"mode":              preflight.ResolvedMode,
		"target_type":       preflight.ResolvedTargetType,
		"profile":           preflight.Profile,
		"include_subfinder": preflight.IncludeSubfinder,
	})
	resolved := opts
	resolved.TargetType = preflight.ResolvedTargetType
	resolved.IncludeSubfinder = preflight.IncludeSubfinder
	resolved.Profile = preflight.Profile
	go s.run(scan, target, resolved)
	return scan, nil
}

func (s *Service) PreflightScan(targetAddr string, mode storage.ScanMode, opts ScanOptions) (PreflightResult, error) {
	resolvedType, normalized, err := resolveTarget(targetAddr, opts.TargetType)
	if err != nil {
		return PreflightResult{}, err
	}

	warnings := make([]string, 0, 2)
	resolvedMode := mode
	if resolvedMode == "" {
		resolvedMode = defaultModeForType(resolvedType)
	}
	switch resolvedMode {
	case storage.ScanInfra, storage.ScanWeb, storage.ScanFull:
	default:
		return PreflightResult{}, fmt.Errorf("invalid scan mode")
	}

	if resolvedType == "url" && resolvedMode == storage.ScanInfra {
		resolvedMode = storage.ScanWeb
		warnings = append(warnings, "modo infra ajustado para web em alvo URL")
	}
	if resolvedType == "ip" && resolvedMode == storage.ScanWeb {
		resolvedMode = storage.ScanInfra
		warnings = append(warnings, "modo web ajustado para infra em alvo IP")
	}

	includeSubfinder := opts.IncludeSubfinder
	if resolvedType != "domain" {
		if includeSubfinder {
			warnings = append(warnings, "subfinder desabilitado: apenas alvos de dominio suportam enumeracao")
		}
		includeSubfinder = false
	}

	profile := strings.TrimSpace(opts.Profile)
	if profile == "" {
		profile = buildProfile(resolvedType, resolvedMode)
	}
	plan := buildExecutionPlan(resolvedType, resolvedMode, includeSubfinder)
	return PreflightResult{
		RawTarget:          strings.TrimSpace(targetAddr),
		NormalizedTarget:   normalized,
		ResolvedTargetType: resolvedType,
		ResolvedMode:       resolvedMode,
		IncludeSubfinder:   includeSubfinder,
		Profile:            profile,
		ExecutionPlan:      plan,
		Warnings:           warnings,
	}, nil
}

func (s *Service) run(scan storage.Scan, target storage.Target, opts ScanOptions) {
	s.workers <- struct{}{}
	defer func() { <-s.workers }()
	s.store.UpdateScanStatus(scan.ID, storage.ScanRunning, "")
	s.emit(scan.ID, "INFO", "start", "scan_started", "Scan iniciado.", 3, map[string]any{"target": target.Address, "mode": scan.Mode})

	assets := []storage.Asset{}
	services := []storage.Service{}
	apps := []storage.Application{}
	vulns := []storage.Vulnerability{}
	stepResults := []storage.ScanStepResult{}
	webTargets := make([]string, 0, 64)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	targetHost := target.Address
	if u, err := url.Parse(target.Address); err == nil && u.Hostname() != "" {
		targetHost = u.Hostname()
	}

	if scan.Mode == storage.ScanWeb || scan.Mode == storage.ScanFull {
		baseWebTarget := target.Address
		if !strings.Contains(baseWebTarget, "://") {
			baseWebTarget = "https://" + baseWebTarget
		}
		webTargets = append(webTargets, baseWebTarget)
	}

	if opts.IncludeSubfinder && net.ParseIP(targetHost) == nil && strings.Contains(targetHost, ".") {
		s.emit(scan.ID, "INFO", "subfinder", "tool_started", "Executando subfinder para enumeracao de subdominios.", 30, map[string]any{"domain": targetHost})
		if subs, err := infra.EnumerateSubdomains(ctx, targetHost); err != nil {
			s.logger.Warn("subfinder_failed", "scan_id", scan.ID, "target", targetHost, "err", err)
			s.emit(scan.ID, "ERROR", "subfinder", "tool_failed", "Subfinder falhou.", 35, map[string]any{"domain": targetHost, "error": err.Error()})
		} else if len(subs) > 0 {
			for _, sub := range subs {
				assets = append(assets, storage.Asset{Host: sub, Platform: "subdomain"})
			}
			if err := os.MkdirAll(filepath.Join(s.outputDir, scan.ID), 0o750); err == nil {
				_ = os.WriteFile(filepath.Join(s.outputDir, scan.ID, "subfinder.txt"), []byte(strings.Join(subs, "\n")+"\n"), 0o640)
			}
			s.emit(scan.ID, "INFO", "subfinder", "tool_completed", "Subfinder concluiu enumeracao.", 42, map[string]any{
				"domain":     targetHost,
				"subdomains": len(subs),
				"artifact":   filepath.Join(s.outputDir, scan.ID, "subfinder.txt"),
			})
			s.logger.Info("subfinder_completed", "scan_id", scan.ID, "target", targetHost, "subdomains", len(subs))

			if scan.Mode == storage.ScanWeb || scan.Mode == storage.ScanFull {
				s.emit(scan.ID, "INFO", "subfinder", "validation_started", "Validando subdominios para varredura Web/API.", 44, map[string]any{"candidates": len(subs)})
				validURLs := validateSubdomainWebTargets(ctx, subs)
				for _, u := range validURLs {
					s.emit(scan.ID, "INFO", "subfinder", "validation_target_ok", "Subdominio valido para Web/API.", 46, map[string]any{"url": u})
				}
				if len(validURLs) == 0 {
					s.emit(scan.ID, "WARN", "subfinder", "validation_empty", "Nenhum subdominio valido para Web/API encontrado.", 47, nil)
				}
				webTargets = mergeUniqueStrings(webTargets, validURLs)
				s.emit(scan.ID, "INFO", "subfinder", "validation_completed", "Validacao de subdominios concluida.", 48, map[string]any{
					"valid_targets": len(validURLs),
					"web_targets":   len(webTargets),
				})
			}
		} else {
			s.emit(scan.ID, "INFO", "subfinder", "tool_completed", "Subfinder nao encontrou subdominios.", 42, map[string]any{"domain": targetHost, "subdomains": 0})
		}
	}

	if scan.Mode == storage.ScanInfra || scan.Mode == storage.ScanFull {
		s.emit(scan.ID, "INFO", "infra", "phase_started", "Iniciando reconhecimento de infraestrutura.", 10, nil)
		a, svc := infra.ScanHost(targetHost)
		assets = append(assets, a...)
		services = append(services, svc...)
		s.emit(scan.ID, "INFO", "infra", "infra_scan_completed", "Reconhecimento de infraestrutura concluido.", 28, map[string]any{
			"host":     targetHost,
			"assets":   len(a),
			"services": len(svc),
		})
	}

	if scan.Mode == storage.ScanWeb || scan.Mode == storage.ScanFull {
		if len(webTargets) == 0 {
			targetURL := target.Address
			if !strings.Contains(targetURL, "://") {
				targetURL = "https://" + targetURL
			}
			webTargets = append(webTargets, targetURL)
		}

		// URL-specific pre webscan: wafw00f -> whatweb -> nmap
		for _, targetURL := range webTargets {
			stepStart := time.Now().UTC()
			// Step: wafw00f
			s.emit(scan.ID, "INFO", "wafw00f", "tool_started", "Identificando WAF (wafw00f).", 38, map[string]any{"target": targetURL})
			wafRes, wafErr := runWafw00f(ctx, targetURL, filepath.Join(s.outputDir, scan.ID))
			if wafErr != nil {
				s.emit(scan.ID, "WARN", "wafw00f", "tool_failed", "wafw00f falhou ou nao instalado.", 39, map[string]any{"error": wafErr.Error(), "target": targetURL})
				stepResults = append(stepResults, storage.ScanStepResult{
					Name:      "wafw00f",
					Category:  "web",
					Status:    "failed",
					Summary:   "wafw00f falhou ou nao instalado",
					Evidence:  wafErr.Error(),
					StartedAt: stepStart, FinishedAt: time.Now().UTC(),
				})
			} else {
				s.emit(scan.ID, "INFO", "wafw00f", "tool_completed", "WAF fingerprint concluido.", 40, map[string]any{"detected": wafRes.Detected, "waf": wafRes.Name})
				// Persist as vulnerability-like info
				if wafRes.Detected {
					vulns = append(vulns, storage.Vulnerability{
						Type:           "waf-detected",
						Severity:       "info",
						Title:          "WAF Detectado",
						Description:    "WAF identificado pelo fingerprint automatico.",
						Evidence:       wafRes.Name,
						Recommendation: "Avaliar bypass controlado para testes autorizados.",
						CreatedAt:      time.Now().UTC(),
					})
				}
				stepResults = append(stepResults, storage.ScanStepResult{
					Name:      "wafw00f",
					Category:  "web",
					Status:    "completed",
					Summary:   summaryWaf(wafRes),
					Severity:  "info",
					Details:   map[string]any{"detected": wafRes.Detected, "waf": wafRes.Name},
					StartedAt: stepStart, FinishedAt: time.Now().UTC(),
				})
			}

			// Step: whatweb
			stepStart = time.Now().UTC()
			s.emit(scan.ID, "INFO", "whatweb", "tool_started", "Fingerprint de tecnologias (whatweb).", 41, map[string]any{"target": targetURL})
			wwRes, wwErr := runWhatweb(ctx, targetURL, filepath.Join(s.outputDir, scan.ID))
			if wwErr != nil {
				s.emit(scan.ID, "WARN", "whatweb", "tool_failed", "whatweb falhou ou nao instalado.", 42, map[string]any{"error": wwErr.Error(), "target": targetURL})
				stepResults = append(stepResults, storage.ScanStepResult{
					Name:      "whatweb",
					Category:  "web",
					Status:    "failed",
					Summary:   "whatweb falhou ou nao instalado",
					Evidence:  wwErr.Error(),
					StartedAt: stepStart, FinishedAt: time.Now().UTC(),
				})
			} else {
				s.emit(scan.ID, "INFO", "whatweb", "tool_completed", "Fingerprint de tecnologias concluido.", 43, map[string]any{"tech": stringSliceLimit(wwRes.Tech, 5)})
				if len(wwRes.Tech) > 0 {
					apps = append(apps, storage.Application{BaseURL: targetURL, AppType: classifyTech(wwRes.Tech), Framework: stringSliceLimit(wwRes.Tech, 8)})
				}
				stepResults = append(stepResults, storage.ScanStepResult{
					Name:      "whatweb",
					Category:  "web",
					Status:    "completed",
					Summary:   "Stack detectado",
					Details:   map[string]any{"tech": wwRes.Tech},
					StartedAt: stepStart, FinishedAt: time.Now().UTC(),
				})
			}

			// Step: nmap top ports (host-level)
			stepStart = time.Now().UTC()
			hostForNmap := targetHost
			if u, err := url.Parse(targetURL); err == nil && u.Hostname() != "" {
				hostForNmap = u.Hostname()
			}
			s.emit(scan.ID, "INFO", "nmap", "tool_started", "Varredura de portas (nmap top 100).", 44, map[string]any{"host": hostForNmap})
			nmapServices, _, nmapErr := runNmapTop(ctx, hostForNmap, filepath.Join(s.outputDir, scan.ID))
			if nmapErr != nil {
				s.emit(scan.ID, "WARN", "nmap", "tool_failed", "nmap falhou ou nao instalado.", 45, map[string]any{"error": nmapErr.Error(), "host": hostForNmap})
				stepResults = append(stepResults, storage.ScanStepResult{
					Name:      "nmap",
					Category:  "infra",
					Status:    "failed",
					Summary:   "nmap falhou ou nao instalado",
					Evidence:  nmapErr.Error(),
					StartedAt: stepStart, FinishedAt: time.Now().UTC(),
				})
			} else {
				// ensure asset exists for host
				if !assetExists(assets, hostForNmap) {
					assets = append(assets, storage.Asset{Host: hostForNmap, Platform: "host"})
				}
				services = append(services, attachHost(nmapServices, hostForNmap)...)
				s.emit(scan.ID, "INFO", "nmap", "tool_completed", "Varredura de portas concluida.", 46, map[string]any{"open_ports": len(nmapServices)})
				stepResults = append(stepResults, storage.ScanStepResult{
					Name:      "nmap",
					Category:  "infra",
					Status:    "completed",
					Summary:   fmt.Sprintf("Portas abertas: %d", len(nmapServices)),
					Details:   map[string]any{"open_ports": len(nmapServices)},
					StartedAt: stepStart, FinishedAt: time.Now().UTC(),
				})
			}
		}

		s.emit(scan.ID, "INFO", "web", "phase_started", "Iniciando varredura Web/API.", 50, nil)
		for _, targetURL := range webTargets {
			stepStart := time.Now().UTC()
			s.emit(scan.ID, "INFO", "web", "target_started", "Iniciando scan Web/API no alvo.", 58, map[string]any{"target": targetURL})
			app, vv := webscan.ScanWeb(ctx, targetURL)
			apps = append(apps, app...)
			vulns = append(vulns, vv...)
			s.emit(scan.ID, "INFO", "web", "target_completed", "Scan Web/API concluido no alvo.", 66, map[string]any{
				"target":          targetURL,
				"applications":    len(app),
				"vulnerabilities": len(vv),
			})
			stepResults = append(stepResults, storage.ScanStepResult{
				Name:      "webscan",
				Category:  "web",
				Status:    "completed",
				Summary:   fmt.Sprintf("Aplicacoes: %d, Vulnerabilidades: %d", len(app), len(vv)),
				Details:   map[string]any{"applications": len(app), "vulnerabilities": len(vv)},
				StartedAt: stepStart, FinishedAt: time.Now().UTC(),
			})
		}
		s.emit(scan.ID, "INFO", "web", "phase_completed", "Varredura Web/API concluida.", 72, map[string]any{
			"targets":         len(webTargets),
			"applications":    len(apps),
			"vulnerabilities": len(vulns),
		})
	}

	s.emit(scan.ID, "INFO", "persist", "phase_started", "Persistindo resultados do scan.", 78, nil)
	s.store.SaveAssets(scan.ID, assets)
	storedAssets, _ := s.store.BuildScanBundle(scan.ID)
	assetID := ""
	if len(storedAssets.Assets) > 0 {
		assetID = storedAssets.Assets[0].ID
	}
	for i := range services {
		services[i].AssetID = assetID
	}
	s.store.SaveServices(scan.ID, services)
	for i := range apps {
		apps[i].AssetID = assetID
	}
	s.store.SaveApplications(scan.ID, apps)
	for i := range vulns {
		vulns[i].TargetID = target.ID
		vulns[i].AssetID = assetID
		if len(apps) > 0 {
			vulns[i].ApplicationID = apps[0].ID
		}
	}
	s.store.SaveVulnerabilities(scan.ID, vulns)
	s.store.SaveStepResults(scan.ID, stepResults)
	s.emit(scan.ID, "INFO", "persist", "phase_completed", "Resultados persistidos.", 84, map[string]any{
		"assets":          len(assets),
		"services":        len(services),
		"applications":    len(apps),
		"vulnerabilities": len(vulns),
	})

	bundle, ok := s.store.BuildScanBundle(scan.ID)
	if !ok {
		s.store.UpdateScanStatus(scan.ID, storage.ScanFailed, "scan bundle not found")
		s.emit(scan.ID, "ERROR", "failed", "scan_failed", "Falha ao montar bundle do scan.", 100, map[string]any{"error": "scan bundle not found"})
		return
	}
	s.emit(scan.ID, "INFO", "correlation", "phase_started", "Correlacionando vulnerabilidades e grafo.", 88, nil)
	nodes, edges := correlation.BuildGraph(scan, target, bundle.Assets, bundle.Services, bundle.Applications, bundle.Vulnerabilities)
	s.store.SaveGraph(scan.ID, nodes, edges)
	chain := correlation.BuildAttackChain(target, bundle.Services, bundle.Applications, bundle.Vulnerabilities)
	s.store.SaveAttackChain(scan.ID, chain)
	s.emit(scan.ID, "INFO", "correlation", "phase_completed", "Correlacao concluida.", 92, map[string]any{
		"graph_nodes": len(nodes),
		"graph_edges": len(edges),
		"chain_steps": len(chain.Steps),
	})

	s.emit(scan.ID, "INFO", "report", "phase_started", "Gerando relatorios.", 95, nil)
	if err := os.MkdirAll(filepath.Join(s.outputDir, scan.ID), 0o750); err == nil {
		if b, ok := s.store.BuildScanBundle(scan.ID); ok {
			_, _ = report.SaveJSON(filepath.Join(s.outputDir, scan.ID), b)
			_, _ = report.SaveHTML(filepath.Join(s.outputDir, scan.ID), b)
		}
	}
	s.emit(scan.ID, "INFO", "report", "phase_completed", "Relatorios gerados.", 98, map[string]any{
		"json": filepath.Join(s.outputDir, scan.ID, "platform-report.json"),
		"html": filepath.Join(s.outputDir, scan.ID, "platform-report.html"),
	})
	s.store.UpdateScanStatus(scan.ID, storage.ScanCompleted, "")
	s.emit(scan.ID, "INFO", "completed", "scan_completed", "Scan finalizado com sucesso.", 100, map[string]any{
		"assets":          len(bundle.Assets),
		"services":        len(bundle.Services),
		"applications":    len(bundle.Applications),
		"vulnerabilities": len(bundle.Vulnerabilities),
	})
	s.logger.Info("platform_scan_completed", "scan_id", scan.ID, "mode", scan.Mode)
}

func assetExists(list []storage.Asset, host string) bool {
	for _, a := range list {
		if strings.EqualFold(a.Host, host) {
			return true
		}
	}
	return false
}

func resolveTarget(targetAddr, targetType string) (string, string, error) {
	raw := strings.TrimSpace(targetAddr)
	if raw == "" {
		return "", "", fmt.Errorf("target required")
	}
	resolvedType := strings.ToLower(strings.TrimSpace(targetType))
	switch resolvedType {
	case "", "auto":
		resolvedType = detectTargetType(raw)
	case "url", "ip", "domain":
	default:
		return "", "", fmt.Errorf("unsupported target type")
	}

	switch resolvedType {
	case "url":
		normalized := raw
		if !strings.Contains(normalized, "://") {
			normalized = "https://" + normalized
		}
		u, err := url.Parse(normalized)
		if err != nil || strings.TrimSpace(u.Scheme) == "" || strings.TrimSpace(u.Host) == "" {
			return "", "", fmt.Errorf("invalid target URL for web scan")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", "", fmt.Errorf("unsupported URL scheme for web scan: %s", u.Scheme)
		}
		u.Host = strings.ToLower(u.Host)
		return resolvedType, u.String(), nil
	case "ip":
		host := strings.TrimSpace(raw)
		if strings.Contains(host, "://") {
			u, err := url.Parse(host)
			if err == nil && u.Hostname() != "" {
				host = u.Hostname()
			}
		}
		host = strings.Trim(host, "/")
		if net.ParseIP(host) == nil {
			return "", "", fmt.Errorf("invalid ip target")
		}
		return resolvedType, host, nil
	default:
		domain := strings.TrimPrefix(strings.TrimPrefix(raw, "http://"), "https://")
		domain = strings.TrimSpace(strings.Trim(domain, "/"))
		if domain == "" || strings.Contains(domain, " ") || strings.Contains(domain, "/") {
			return "", "", fmt.Errorf("invalid domain target")
		}
		if net.ParseIP(domain) != nil {
			return "", "", fmt.Errorf("domain target cannot be an ip")
		}
		return resolvedType, strings.ToLower(domain), nil
	}
}

func detectTargetType(raw string) string {
	v := strings.TrimSpace(raw)
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil && net.ParseIP(u.Hostname()) != nil {
			return "ip"
		}
		return "url"
	}
	if net.ParseIP(strings.Trim(v, "/")) != nil {
		return "ip"
	}
	if strings.Contains(v, "/") || strings.Contains(v, "?") || strings.Contains(v, "#") {
		return "url"
	}
	return "domain"
}

func defaultModeForType(targetType string) storage.ScanMode {
	switch targetType {
	case "url":
		return storage.ScanWeb
	case "ip":
		return storage.ScanInfra
	default:
		return storage.ScanFull
	}
}

func buildProfile(targetType string, mode storage.ScanMode) string {
	switch targetType {
	case "url":
		return "url-web-fast"
	case "ip":
		return "ip-infra-focused"
	default:
		if mode == storage.ScanInfra {
			return "domain-infra-recon"
		}
		if mode == storage.ScanWeb {
			return "domain-web-api"
		}
		return "domain-full-recon"
	}
}

func buildExecutionPlan(targetType string, mode storage.ScanMode, includeSubfinder bool) ExecutionPlan {
	phases := make([]string, 0, 6)
	tools := make([]string, 0, 8)
	notes := make([]string, 0, 6)

	if mode == storage.ScanInfra || mode == storage.ScanFull {
		phases = append(phases, "infra-recon")
		tools = append(tools, "tcp-connect-scanner", "service-fingerprint")
		if targetType == "domain" && includeSubfinder {
			tools = append(tools, "subfinder")
			notes = append(notes, "enumeracao de subdominios ativa para ampliar superficie")
		}
	}
	if mode == storage.ScanWeb || mode == storage.ScanFull {
		phases = append(phases, "web-fingerprint", "web-crawl", "web-api-tests")
		tools = append(tools, "wafw00f", "whatweb", "nmap-top100", "crawler", "passive-checks", "sqli-module", "xss-module", "jwt-module", "bola-module", "ssrf-module")
		notes = append(notes, "sequencia URL: wafw00f → whatweb → nmap → web/api modules")
	}
	phases = append(phases, "correlation", "report")
	notes = append(notes, "scan respeita limite interno de concorrencia e rate-limit")
	return ExecutionPlan{Phases: phases, Tools: tools, Notes: notes}
}

func validateSubdomainWebTargets(ctx context.Context, subdomains []string) []string {
	client := &http.Client{Timeout: 4 * time.Second}
	out := make([]string, 0, len(subdomains))
	for _, sub := range subdomains {
		sub = strings.TrimSpace(strings.ToLower(sub))
		if sub == "" {
			continue
		}
		if u, ok := probeHTTP(ctx, client, "https://"+sub); ok {
			out = append(out, u)
			continue
		}
		if u, ok := probeHTTP(ctx, client, "http://"+sub); ok {
			out = append(out, u)
		}
	}
	return out
}

func probeHTTP(ctx context.Context, client *http.Client, raw string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 100 && resp.StatusCode < 600 {
		return raw, true
	}
	return "", false
}

func mergeUniqueStrings(base []string, more []string) []string {
	seen := make(map[string]struct{}, len(base)+len(more))
	for _, v := range base {
		seen[v] = struct{}{}
	}
	for _, v := range more {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		base = append(base, v)
	}
	return base
}

func (s *Service) emit(scanID, level, phase, kind, message string, progressValue int, data map[string]any) {
	if s.progress == nil || scanID == "" {
		return
	}
	ev := s.progress.Publish(progress.ScanEvent{
		ScanID:   scanID,
		Level:    level,
		Phase:    phase,
		Kind:     kind,
		Message:  message,
		Progress: progressValue,
		Data:     data,
	})
	// Emit also to logger for container logs visibility.
	if s.logger != nil {
		var lvl slog.Level
		switch strings.ToUpper(level) {
		case "ERROR":
			lvl = slog.LevelError
		case "WARN":
			lvl = slog.LevelWarn
		default:
			lvl = slog.LevelInfo
		}
		args := []any{
			"scan_id", ev.ScanID,
			"phase", ev.Phase,
			"kind", ev.Kind,
			"message", ev.Message,
			"progress", ev.Progress,
		}
		if len(ev.Data) > 0 {
			args = append(args, "data", ev.Data)
		}
		s.logger.Log(context.Background(), lvl, "scan_event", args...)
	}
	s.persistEvent(ev)
}

func (s *Service) persistEvent(ev progress.ScanEvent) {
	if ev.ScanID == "" {
		return
	}
	dir := filepath.Join(s.outputDir, ev.ScanID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "events.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
}
