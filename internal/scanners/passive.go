package scanners

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"scannn3d/internal/core"
	"scannn3d/internal/request"
)

type PassiveScanner struct{}

func NewPassiveScanner() *PassiveScanner { return &PassiveScanner{} }

func (s *PassiveScanner) Name() string { return "passive" }

func (s *PassiveScanner) Scan(ctx context.Context, tr core.TargetRequest, rm *request.Manager) ([]core.Finding, error) {
	req, err := buildRequest(ctx, tr, tr.URL)
	if err != nil {
		return nil, err
	}
	res, err := rm.Do(ctx, req)
	if err != nil {
		return nil, err
	}

	findings := make([]core.Finding, 0, 8)
	findings = append(findings, checkSecurityHeaders(tr, res.Response.Header, res.RawRequest, res.RawResponse)...)
	findings = append(findings, checkCORS(tr, res.Response.Header, res.RawRequest, res.RawResponse)...)
	findings = append(findings, checkCookies(tr, res.Response.Header, res.RawRequest, res.RawResponse)...)
	findings = append(findings, checkInfoLeak(tr, res.Body, res.Response.Header, res.RawRequest, res.RawResponse)...)
	findings = append(findings, checkTLS(tr, res.Response, res.RawRequest, res.RawResponse)...)
	return findings, nil
}

func checkSecurityHeaders(tr core.TargetRequest, h http.Header, rawReq, rawResp string) []core.Finding {
	required := map[string]string{
		"X-Content-Type-Options":    "Set X-Content-Type-Options: nosniff.",
		"X-Frame-Options":           "Set X-Frame-Options to DENY or SAMEORIGIN.",
		"Content-Security-Policy":   "Define strict CSP with nonces/hashes.",
		"Referrer-Policy":           "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
		"Strict-Transport-Security": "Set Strict-Transport-Security with long max-age and includeSubDomains for HTTPS services.",
		"Permissions-Policy":        "Define restrictive Permissions-Policy to disable unused browser features.",
	}
	out := make([]core.Finding, 0, len(required))
	for key, rec := range required {
		if strings.TrimSpace(h.Get(key)) == "" {
			out = append(out, buildFindingWithFullEvid(
				"passive",
				"medium",
				"Missing Security Header",
				"Security-relevant HTTP header is missing.",
				tr.URL,
				tr.Method,
				fmt.Sprintf("missing_header=%s", key),
				rec,
				rawReq,
				rawResp,
			))
		}
	}
	return out
}

func checkCORS(tr core.TargetRequest, h http.Header, rawReq, rawResp string) []core.Finding {
	origin := strings.TrimSpace(h.Get("Access-Control-Allow-Origin"))
	cred := strings.TrimSpace(strings.ToLower(h.Get("Access-Control-Allow-Credentials")))
	vary := strings.TrimSpace(strings.ToLower(h.Get("Vary")))
	if origin == "*" && cred == "true" {
		return []core.Finding{buildFindingWithFullEvid(
			"passive",
			"high",
			"Insecure CORS Policy",
			"Wildcard ACAO combined with credentials can expose authenticated data cross-origin.",
			tr.URL,
			tr.Method,
			"Access-Control-Allow-Origin=* and Access-Control-Allow-Credentials=true",
			"Restrict allowed origins explicitly and avoid credentials with wildcard.",
			rawReq,
			rawResp,
		)}
	}
	if origin != "" && origin != "*" && cred == "true" && !strings.Contains(vary, "origin") {
		return []core.Finding{buildFindingWithFullEvid(
			"passive",
			"medium",
			"Potential Dynamic CORS Trust",
			"Credentials are enabled with specific origin but response may miss proper Vary: Origin behavior.",
			tr.URL,
			tr.Method,
			fmt.Sprintf("acao=%q acac=%q vary=%q", origin, cred, vary),
			"Ensure strict origin allowlist and include Vary: Origin for dynamic CORS decisions.",
			rawReq,
			rawResp,
		)}
	}
	return nil
}

func checkCookies(tr core.TargetRequest, h http.Header, rawReq, rawResp string) []core.Finding {
	cookies := h.Values("Set-Cookie")
	out := make([]core.Finding, 0, len(cookies))
	for _, c := range cookies {
		cl := strings.ToLower(c)
		if !strings.Contains(cl, "secure") || !strings.Contains(cl, "httponly") {
			out = append(out, buildFindingWithFullEvid(
				"passive",
				"medium",
				"Weak Cookie Flags",
				"Cookie missing Secure and/or HttpOnly flags.",
				tr.URL,
				tr.Method,
				c,
				"Set Secure, HttpOnly and SameSite attributes on sensitive cookies.",
				rawReq,
				rawResp,
			))
		}
		if !strings.Contains(cl, "samesite=") {
			out = append(out, buildFindingWithFullEvid(
				"passive",
				"low",
				"Cookie Missing SameSite",
				"Cookie does not define SameSite attribute.",
				tr.URL,
				tr.Method,
				c,
				"Set SameSite=Lax or SameSite=Strict for session cookies.",
				rawReq,
				rawResp,
			))
		}
	}
	return out
}

func checkInfoLeak(tr core.TargetRequest, body []byte, h http.Header, rawReq, rawResp string) []core.Finding {
	out := make([]core.Finding, 0, 3)
	if server := strings.TrimSpace(h.Get("Server")); server != "" {
		out = append(out, buildFindingWithFullEvid(
			"passive",
			"low",
			"Server Banner Exposed",
			"Server header discloses backend technology.",
			tr.URL,
			tr.Method,
			"Server="+server,
			"Minimize or normalize technology banners at edge/proxy layer.",
			rawReq,
			rawResp,
		))
	}
	b := strings.ToLower(string(body))
	markers := []string{"stack trace", "exception in thread", "sql syntax", "aws_secret_access_key", "api_key", "bearer "}
	if ok, marker := containsAny(b, markers); ok {
		out = append(out, buildFindingWithFullEvid(
			"passive",
			"medium",
			"Potential Information Disclosure",
			"Response body contains sensitive error/debug/credential marker.",
			tr.URL,
			tr.Method,
			"marker="+marker,
			"Disable debug output and scrub secrets/errors from API responses.",
			rawReq,
			rawResp,
		))
	}
	return out
}

func checkTLS(tr core.TargetRequest, resp *http.Response, rawReq, rawResp string) []core.Finding {
	if resp.TLS == nil {
		return nil
	}
	if resp.TLS.Version < 0x0303 {
		return []core.Finding{buildFindingWithFullEvid(
			"passive",
			"medium",
			"Weak TLS Version",
			"Target negotiated TLS version below 1.2.",
			tr.URL,
			tr.Method,
			fmt.Sprintf("tls_version=0x%x", resp.TLS.Version),
			"Enforce TLS 1.2+ and disable deprecated protocol versions.",
			rawReq,
			rawResp,
		)}
	}
	return nil
}
