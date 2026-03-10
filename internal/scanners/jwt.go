package scanners

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"scannn3d/internal/core"
	"scannn3d/internal/request"
)

type JWTScanner struct{}

func NewJWTScanner() *JWTScanner { return &JWTScanner{} }

func (s *JWTScanner) Name() string { return "jwt" }

func (s *JWTScanner) Scan(ctx context.Context, tr core.TargetRequest, rm *request.Manager) ([]core.Finding, error) {
	authHeader := tr.Headers.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return nil, nil
	}
	originalToken := strings.TrimSpace(authHeader[len("Bearer "):])
	parts := strings.Split(originalToken, ".")
	if len(parts) != 3 {
		return nil, nil
	}

	baseStatus, _, err := baseline(ctx, tr, rm)
	if err != nil {
		return nil, err
	}

	noneHeader := map[string]any{"alg": "none", "typ": "JWT"}
	hBytes, _ := json.Marshal(noneHeader)
	noneToken := base64.RawURLEncoding.EncodeToString(hBytes) + "." + parts[1] + "."

	findings := make([]core.Finding, 0, 2)

	// Check 1: alg=none bypass.
	if accepted, res, reqErr := s.testToken(ctx, tr, rm, noneToken); reqErr == nil && accepted {
		findings = append(findings, buildFindingWithFullEvid(
			s.Name(),
			"high",
			"Potential JWT 'alg=none' Acceptance",
			"Endpoint accepted unsigned JWT token with alg=none.",
			tr.URL,
			tr.Method,
			fmt.Sprintf("status=%d baseline_status=%d token_prefix=%s", res.Response.StatusCode, baseStatus, noneToken[:min(24, len(noneToken))]),
			"Enforce strict JWT algorithm validation and reject unsigned tokens.",
			res.RawRequest,
			res.RawResponse,
		))
	}

	// Check 2: signature tampering acceptance.
	tamperedPayload := s.buildTamperedPayload(parts[1])
	if tamperedPayload != "" {
		tamperedToken := parts[0] + "." + tamperedPayload + "." + parts[2]
		if accepted, res, reqErr := s.testToken(ctx, tr, rm, tamperedToken); reqErr == nil && accepted {
			findings = append(findings, buildFindingWithFullEvid(
				s.Name(),
				"critical",
				"Potential JWT Signature Bypass",
				"Endpoint accepted JWT token with modified claims but original signature.",
				tr.URL,
				tr.Method,
				fmt.Sprintf("status=%d baseline_status=%d", res.Response.StatusCode, baseStatus),
				"Require strict signature verification and reject any token with invalid signature.",
				res.RawRequest,
				res.RawResponse,
			))
		}
	}

	return findings, nil
}

func (s *JWTScanner) testToken(ctx context.Context, tr core.TargetRequest, rm *request.Manager, token string) (bool, *request.Result, error) {
	req, err := buildRequest(ctx, tr, tr.URL)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := rm.Do(ctx, req)
	if err != nil {
		return false, nil, err
	}
	return res.Response.StatusCode < 400, res, nil
}

func (s *JWTScanner) buildTamperedPayload(payloadPart string) string {
	raw, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return ""
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return ""
	}
	claims["role"] = "admin"
	claims["admin"] = true
	claims["sub"] = "1"
	encoded, err := json.Marshal(claims)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
