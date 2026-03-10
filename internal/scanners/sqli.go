package scanners

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"scannn3d/internal/core"
	"scannn3d/internal/request"
)

type SQLiScanner struct{}

func NewSQLiScanner() *SQLiScanner { return &SQLiScanner{} }

func (s *SQLiScanner) Name() string { return "sqli" }

func (s *SQLiScanner) Scan(ctx context.Context, tr core.TargetRequest, rm *request.Manager) ([]core.Finding, error) {
	baseStatus, baseBody, baseLatency, err := s.baselineWithLatency(ctx, tr, rm)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(tr.URL)
	if err != nil {
		return nil, err
	}

	keys := paramKeys(u)
	errorPayloads := []string{
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"1' ORDER BY 999--",
		"' UNION SELECT NULL--",
	}
	booleanPairs := [][2]string{
		{"' AND '1'='1", "' AND '1'='2"},
		{"\" AND \"1\"=\"1", "\" AND \"1\"=\"2"},
	}
	timePayloads := []string{
		"' AND SLEEP(3)--",
		"';WAITFOR DELAY '0:0:3'--",
		"'||pg_sleep(3)--",
	}
	errors := []string{"sql syntax", "mysql", "psql", "sqlite", "odbc", "database error", "syntax error"}
	findings := make([]core.Finding, 0, 8)

	for _, key := range keys {
		// Error-based probing.
		for _, payload := range errorPayloads {
			mURL, err := mutateQuery(tr.URL, key, payload)
			if err != nil {
				continue
			}
			req, err := buildRequest(ctx, tr, mURL)
			if err != nil {
				continue
			}
			res, err := rm.Do(ctx, req)
			if err != nil {
				continue
			}
			bodyStr := string(res.Body)
			if ok, matched := containsAny(bodyStr, errors); ok || (res.Response.StatusCode >= 500 && baseStatus < 500) {
				findings = append(findings, buildFindingWithFullEvid(
					s.Name(),
					"high",
					"Potential SQL Injection (Error-Based)",
					"Input mutation produced database-like errors or server-side fault transition.",
					mURL,
					tr.Method,
					fmt.Sprintf("param=%s payload=%q status=%d marker=%q baseline_status=%d baseline_len=%d", key, payload, res.Response.StatusCode, matched, baseStatus, len(baseBody)),
					"Use parameterized queries, strict input validation, and suppress SQL error leakage.",
					res.RawRequest,
					res.RawResponse,
				))
				break
			}
		}

		// Boolean-based differential probing.
		for _, pair := range booleanPairs {
			trueURL, err := mutateQuery(tr.URL, key, pair[0])
			if err != nil {
				continue
			}
			falseURL, err := mutateQuery(tr.URL, key, pair[1])
			if err != nil {
				continue
			}
			trueRes, errTrue := s.fetch(ctx, tr, rm, trueURL)
			falseRes, errFalse := s.fetch(ctx, tr, rm, falseURL)
			if errTrue != nil || errFalse != nil {
				continue
			}
			simTrueBase := roughSimilarity(string(trueRes.Body), baseBody)
			simFalseBase := roughSimilarity(string(falseRes.Body), baseBody)
			statusFlip := trueRes.Response.StatusCode < 400 && falseRes.Response.StatusCode >= 400
			if statusFlip || (simTrueBase >= 0.92 && simFalseBase <= 0.75) {
				findings = append(findings, buildFindingWithFullEvid(
					s.Name(),
					"high",
					"Potential SQL Injection (Boolean-Based)",
					"True/false SQL condition mutation generated divergent server behavior consistent with injectable query logic.",
					trueURL,
					tr.Method,
					fmt.Sprintf("param=%s true_status=%d false_status=%d sim_true_base=%.2f sim_false_base=%.2f", key, trueRes.Response.StatusCode, falseRes.Response.StatusCode, simTrueBase, simFalseBase),
					"Use prepared statements and canonicalize validation before query construction.",
					trueRes.RawRequest,
					trueRes.RawResponse,
				))
				break
			}
		}

		// Time-based probing.
		for _, payload := range timePayloads {
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
			if res.Response.StatusCode < 500 && elapsed > baseLatency+(1500*time.Millisecond) && elapsed >= (2500*time.Millisecond) {
				findings = append(findings, buildFindingWithFullEvid(
					s.Name(),
					"medium",
					"Potential SQL Injection (Time-Based)",
					"Time-delay payload significantly increased response latency compared with baseline.",
					mURL,
					tr.Method,
					fmt.Sprintf("param=%s payload=%q baseline_ms=%d observed_ms=%d", key, payload, baseLatency.Milliseconds(), elapsed.Milliseconds()),
					"Investigate dynamic SQL execution paths and enforce parameterized statements.",
					res.RawRequest,
					res.RawResponse,
				))
				break
			}
		}
	}

	return findings, nil
}

func (s *SQLiScanner) fetch(ctx context.Context, tr core.TargetRequest, rm *request.Manager, rawURL string) (*request.Result, error) {
	req, err := buildRequest(ctx, tr, rawURL)
	if err != nil {
		return nil, err
	}
	res, err := rm.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *SQLiScanner) baselineWithLatency(ctx context.Context, tr core.TargetRequest, rm *request.Manager) (int, string, time.Duration, error) {
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
