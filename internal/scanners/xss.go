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

type XSSScanner struct{}

func NewXSSScanner() *XSSScanner { return &XSSScanner{} }

func (s *XSSScanner) Name() string { return "xss" }

func (s *XSSScanner) Scan(ctx context.Context, tr core.TargetRequest, rm *request.Manager) ([]core.Finding, error) {
	u, err := url.Parse(tr.URL)
	if err != nil {
		return nil, err
	}
	keys := paramKeys(u)
	findings := make([]core.Finding, 0, 4)

	for _, key := range keys {
		// 1. Probing for reflection context.
		probeMarker := fmt.Sprintf("xssprobe%d", time.Now().UnixNano())
		mURL, _ := mutateQuery(tr.URL, key, probeMarker)
		req, _ := buildRequest(ctx, tr, mURL)
		res, err := rm.Do(ctx, req)
		if err != nil {
			continue
		}
		bodyStr := string(res.Body)
		if !strings.Contains(bodyStr, probeMarker) {
			continue
		}

		// 2. Context detection and targeted payload selection.
		payloads := s.detectContextPayloads(bodyStr, probeMarker)
		for _, p := range payloads {
			mURL, _ := mutateQuery(tr.URL, key, p)
			req, _ := buildRequest(ctx, tr, mURL)
			res, err := rm.Do(ctx, req)
			if err != nil {
				continue
			}
			if s.isExploited(string(res.Body), p) {
				findings = append(findings, buildFindingWithFullEvid(
					s.Name(),
					"high",
					"Potential Reflected XSS",
					"Injected payload was reflected and appears to be executable in the detected context.",
					mURL,
					tr.Method,
					fmt.Sprintf("param=%s payload=%q context_detected=true", key, p),
					"CONTEXT_ENCODING: Use contextual output encoding (e.g., HTML entity encoding for body, attribute encoding for attributes) and enforce a strict Content Security Policy.",
					res.RawRequest,
					res.RawResponse,
				))
				break
			}
		}
	}
	return findings, nil
}

func (s *XSSScanner) detectContextPayloads(body, marker string) []string {
	// Simple index-based context detection.
	idx := strings.Index(body, marker)
	if idx == -1 {
		return nil
	}

	// Basic heuristic: check surrounding chars.
	pre := ""
	if idx > 20 {
		pre = strings.ToLower(body[idx-20 : idx])
	} else {
		pre = strings.ToLower(body[:idx])
	}

	// 1. Script context.
	if strings.Contains(pre, "<script") {
		return []string{"';alert(1)//", "\"-alert(1)-\""}
	}
	// 2. Attribute context.
	if strings.Contains(pre, "=") && !strings.Contains(pre, ">") {
		return []string{"\" onmouseover=alert(1) \"", "' onmouseover=alert(1) '"}
	}
	// 3. Default (HTML Body) context.
	return []string{"<script>alert(1)</script>", "<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"}
}

func (s *XSSScanner) isExploited(body, payload string) bool {
	// If the verbatim payload is reflected and looks like a tag or break-out, we flag it.
	return strings.Contains(body, payload)
}
