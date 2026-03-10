package scanners

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"scannn3d/internal/core"
	"scannn3d/internal/request"
)

type SSRFScanner struct{}

func NewSSRFScanner() *SSRFScanner { return &SSRFScanner{} }

func (s *SSRFScanner) Name() string { return "ssrf" }

func (s *SSRFScanner) Scan(ctx context.Context, tr core.TargetRequest, rm *request.Manager) ([]core.Finding, error) {
	baseStatus, _, baseLatency, err := s.baselineWithLatency(ctx, tr, rm)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(tr.URL)
	if err != nil {
		return nil, err
	}

	keys := paramKeys(u)
	payloads := []string{
		"http://127.0.0.1:80",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]/",
		"http://localhost:22/",
		"file:///etc/passwd",
	}
	candidates := []string{"url", "uri", "path", "next", "dest", "redirect", "callback", "image", "link", "feed", "target", "return", "continue"}
	findings := make([]core.Finding, 0, 6)

	for _, key := range keys {
		matched := false
		for _, c := range candidates {
			if strings.Contains(strings.ToLower(key), c) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		for _, payload := range payloads {
			mURL, err := mutateQuery(tr.URL, key, payload)
			if err != nil {
				continue
			}
			req, err := buildRequest(ctx, tr, mURL)
			if err != nil {
				continue
			}
			start := time.Now()
			res, err := rm.Do(ctx, req)
			if err != nil {
				continue
			}
			elapsed := time.Since(start)
			bodyStr := string(res.Body)
			location := strings.ToLower(res.Response.Header.Get("Location"))
			if ok, marker := containsAny(bodyStr, []string{"connection refused", "no route to host", "timeout", "metadata", "169.254.169.254", "root:x:0:0"}); ok {
				findings = append(findings, buildFindingWithFullEvid(
					s.Name(),
					"high",
					"Potential SSRF",
					"URL-like parameter appears to be fetched server-side and returned backend/network indicators.",
					mURL,
					tr.Method,
					fmt.Sprintf("param=%s payload=%q status=%d marker=%q", key, payload, res.Response.StatusCode, marker),
					"Apply strict allowlist validation for outbound destinations and block internal/link-local schemes.",
					res.RawRequest,
					res.RawResponse,
				))
				break
			}
			if res.Response.StatusCode >= 500 && baseStatus < 500 {
				findings = append(findings, buildFindingWithFullEvid(
					s.Name(),
					"medium",
					"Potential SSRF Sink",
					"Mutation on URL-like parameter caused backend fault transition.",
					mURL,
					tr.Method,
					fmt.Sprintf("param=%s payload=%q baseline_status=%d mutated_status=%d baseline_ms=%d observed_ms=%d", key, payload, baseStatus, res.Response.StatusCode, baseLatency.Milliseconds(), elapsed.Milliseconds()),
					"Review server-side URL fetch logic and enforce destination allowlist controls.",
					res.RawRequest,
					res.RawResponse,
				))
				break
			}
			if strings.Contains(location, "169.254.169.254") || strings.Contains(location, "localhost") || strings.Contains(location, "127.0.0.1") {
				findings = append(findings, buildFindingWithFullEvid(
					s.Name(),
					"medium",
					"Potential SSRF / Redirect Pivot",
					"Location header indicates redirection/pivot to internal destination.",
					mURL,
					tr.Method,
					fmt.Sprintf("param=%s payload=%q status=%d location=%q", key, payload, res.Response.StatusCode, location),
					"Validate redirect targets and disallow internal network destinations.",
					res.RawRequest,
					res.RawResponse,
				))
				break
			}
			if elapsed > baseLatency+(2*time.Second) && elapsed >= 3*time.Second {
				findings = append(findings, buildFindingWithFullEvid(
					s.Name(),
					"low",
					"Potential SSRF Timing Anomaly",
					"URL mutation produced unusual backend latency spike on URL-like parameter.",
					mURL,
					tr.Method,
					fmt.Sprintf("param=%s payload=%q baseline_ms=%d observed_ms=%d", key, payload, baseLatency.Milliseconds(), elapsed.Milliseconds()),
					"Review outbound request handlers and enforce strict destination validation.",
					res.RawRequest,
					res.RawResponse,
				))
				break
			}
		}
	}

	return findings, nil
}

func (s *SSRFScanner) baselineWithLatency(ctx context.Context, tr core.TargetRequest, rm *request.Manager) (int, string, time.Duration, error) {
	req, err := buildRequest(ctx, tr, tr.URL)
	if err != nil {
		return 0, "", 0, err
	}
	start := time.Now()
	res, err := rm.Do(ctx, req)
	if err != nil {
		return 0, "", 0, err
	}
	return res.Response.StatusCode, string(res.Body), time.Since(start), nil
}
