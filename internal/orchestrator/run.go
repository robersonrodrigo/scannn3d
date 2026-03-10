package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"scannn3d/internal/config"
	"scannn3d/internal/core"
	"scannn3d/internal/discovery"
	"scannn3d/internal/exttools"
	"scannn3d/internal/ratelimit"
	"scannn3d/internal/report"
	"scannn3d/internal/request"
	"scannn3d/internal/scanners"
	"scannn3d/internal/scope"
)

type ExecuteResult struct {
	Report          report.Report
	ExternalResults []extools.Result
}

type Hooks struct {
	PhaseHook          func(phase string, progress int)
	ExternalStatusHook func(result extools.Result)
}

func Execute(ctx context.Context, cfg *config.Config, logger *slog.Logger) (ExecuteResult, error) {
	return ExecuteWithHooks(ctx, cfg, logger, Hooks{})
}

func ExecuteWithHooks(ctx context.Context, cfg *config.Config, logger *slog.Logger, hooks Hooks) (ExecuteResult, error) {
	if hooks.PhaseHook != nil {
		hooks.PhaseHook("discovery", 10)
	}
	sc := scope.New(cfg.ScopeHosts)
	lim := ratelimit.New(cfg.Rate, cfg.Burst)
	rm := request.New(cfg.Timeout, cfg.InsecureTLS, lim, sc, logger, cfg.Auth)

	selected, err := scanners.Select(cfg.Modules, cfg.TemplateDir, logger)
	if err != nil {
		return ExecuteResult{}, err
	}

	urls, err := discovery.BuildTargets(ctx, cfg, rm, logger)
	if err != nil {
		return ExecuteResult{}, err
	}
	logger.Info("discovery_completed", "target_count", len(urls))
	targets, err := buildTargets(cfg, urls)
	if err != nil {
		return ExecuteResult{}, err
	}
	if hooks.PhaseHook != nil {
		hooks.PhaseHook("scanning", 40)
	}

	engine := core.New(selected, rm, cfg.Concurrency, logger)
	start := time.Now()
	findings, err := engine.Run(ctx, targets)
	if err != nil {
		return ExecuteResult{}, err
	}
	if hooks.PhaseHook != nil {
		hooks.PhaseHook("external_tools", 70)
	}
	externalFindings, externalResults, err := extools.Run(ctx, cfg, cfg.OutputDir, logger, hooks.ExternalStatusHook)
	if err != nil {
		logger.Warn("external_tools_error", "err", err)
	} else if len(externalFindings) > 0 {
		findings = append(findings, externalFindings...)
	}
	elapsed := time.Since(start)
	rep := report.Build(findings, cfg.Target, elapsed)
	if hooks.PhaseHook != nil {
		hooks.PhaseHook("finalizing", 95)
	}
	return ExecuteResult{Report: rep, ExternalResults: externalResults}, nil
}

func buildTargets(cfg *config.Config, urls []string) ([]core.TargetRequest, error) {
	h := make(http.Header, len(cfg.Headers)+1)
	for k, v := range cfg.Headers {
		h.Set(k, v)
	}
	if cfg.Auth.Type == config.AuthBearer && cfg.Auth.Token != "" {
		h.Set("Authorization", "Bearer "+cfg.Auth.Token)
	}

	targets := make([]core.TargetRequest, 0, len(urls))
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid discovered url %q: %w", raw, err)
		}
		targets = append(targets, core.TargetRequest{
			Method:  strings.ToUpper(cfg.Method),
			URL:     u.String(),
			Headers: h.Clone(),
			Body:    cfg.Body,
		})
	}
	return targets, nil
}
