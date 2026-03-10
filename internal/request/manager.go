package request

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"time"

	"scannn3d/internal/auth"
	"scannn3d/internal/config"
	"scannn3d/internal/ratelimit"
	"scannn3d/internal/scope"
)

type Manager struct {
	client *http.Client
	lim    *ratelimit.Limiter
	scope  *scope.Controller
	logger *slog.Logger
	auth   config.AuthConfig
	agents []string
}

var defaultUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
}

func New(timeout time.Duration, insecureTLS bool, lim *ratelimit.Limiter, sc *scope.Controller, logger *slog.Logger, authCfg config.AuthConfig) *Manager {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecureTLS}
	return &Manager{
		client: &http.Client{Timeout: timeout, Transport: transport},
		lim:    lim,
		scope:  sc,
		logger: logger,
		auth:   authCfg,
		agents: defaultUserAgents,
	}
}

type Result struct {
	Response    *http.Response
	Body        []byte
	RawRequest  string
	RawResponse string
}

func (m *Manager) Do(ctx context.Context, req *http.Request) (*Result, error) {
	if err := m.scope.Validate(req.URL.String()); err != nil {
		return nil, err
	}
	if err := m.lim.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter wait failed: %w", err)
	}
	if err := auth.Apply(req, m.auth); err != nil {
		return nil, err
	}

	if req.Header.Get("User-Agent") == "" && len(m.agents) > 0 {
		req.Header.Set("User-Agent", m.agents[rand.Intn(len(m.agents))])
	}

	rawReq, _ := httputil.DumpRequestOut(req, true)

	start := time.Now()
	resp, err := m.client.Do(req)
	if err != nil {
		if m.logger != nil {
			m.logger.Warn("request_failed", "method", req.Method, "url", req.URL.String(), "err", err)
		}
		return nil, err
	}
	defer resp.Body.Close()

	rawResp, _ := httputil.DumpResponse(resp, true)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if m.logger != nil {
		m.logger.Debug("request_completed", "method", req.Method, "url", req.URL.String(), "status", resp.StatusCode, "latency_ms", time.Since(start).Milliseconds())
	}
	return &Result{
		Response:    resp,
		Body:        body,
		RawRequest:  string(rawReq),
		RawResponse: string(rawResp),
	}, nil
}
