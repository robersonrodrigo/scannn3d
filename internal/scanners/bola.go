package scanners

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"scannn3d/internal/core"
	"scannn3d/internal/request"
)

type BOLAScanner struct{}

func NewBOLAScanner() *BOLAScanner { return &BOLAScanner{} }

func (s *BOLAScanner) Name() string { return "bola" }

var idParams = []string{"id", "user_id", "userid", "account_id", "order_id", "profile_id"}

func (s *BOLAScanner) Scan(ctx context.Context, tr core.TargetRequest, rm *request.Manager) ([]core.Finding, error) {
	baseStatus, baseBody, err := baseline(ctx, tr, rm)
	if err != nil {
		return nil, err
	}

	findings := make([]core.Finding, 0, 2)

	pathMutations := MutatePathIDs(tr.URL)
	for _, mURL := range pathMutations {
		f, err := s.compare(ctx, tr, rm, baseStatus, baseBody, mURL, "path")
		if err == nil && f != nil {
			findings = append(findings, *f)
		}
	}

	u, err := url.Parse(tr.URL)
	if err == nil {
		q := u.Query()
		for _, p := range idParams {
			if val := q.Get(p); val != "" {
				n, convErr := strconv.Atoi(val)
				if convErr != nil {
					continue
				}
				for _, cand := range []int{n + 1, n - 1} {
					q.Set(p, strconv.Itoa(cand))
					u.RawQuery = q.Encode()
					f, err := s.compare(ctx, tr, rm, baseStatus, baseBody, u.String(), "query")
					if err == nil && f != nil {
						findings = append(findings, *f)
					}
				}
			}
		}
	}

	return findings, nil
}

func (s *BOLAScanner) compare(ctx context.Context, tr core.TargetRequest, rm *request.Manager, baseStatus int, baseBody, mURL, location string) (*core.Finding, error) {
	req, err := buildRequest(ctx, tr, mURL)
	if err != nil {
		return nil, err
	}
	res, err := rm.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	bodyStr := string(res.Body)
	baseSim := roughSimilarity(baseBody, bodyStr)
	if baseStatus < 400 && res.Response.StatusCode < 400 && bodyStr != baseBody {
		if ok, _ := containsAny(bodyStr, []string{"forbidden", "unauthorized", "not allowed"}); !ok {
			f := buildFindingWithFullEvid(
				s.Name(),
				"high",
				"Potential BOLA/IDOR",
				"Resource identifier mutation returned another accessible object without authorization failure.",
				mURL,
				tr.Method,
				fmt.Sprintf("mutation=%s base_status=%d mutated_status=%d body_similarity=%.2f", location, baseStatus, res.Response.StatusCode, baseSim),
				"Enforce object-level authorization checks for every resource access.",
				res.RawRequest,
				res.RawResponse,
			)
			return &f, nil
		}
	}
	return nil, nil
}
