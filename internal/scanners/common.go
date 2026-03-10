package scanners

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"scannn3d/internal/core"
	"scannn3d/internal/request"
)

var numRe = regexp.MustCompile(`\d+`)

func MutatePathIDs(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	segments := strings.Split(u.Path, "/")
	out := make([]string, 0, 2)
	for i, seg := range segments {
		if !numRe.MatchString(seg) {
			continue
		}
		n, err := strconv.Atoi(seg)
		if err != nil {
			continue
		}
		for _, cand := range []int{n + 1, n - 1} {
			copySeg := append([]string(nil), segments...)
			copySeg[i] = strconv.Itoa(cand)
			u.Path = strings.Join(copySeg, "/")
			out = append(out, u.String())
		}
	}
	return out
}

func buildRequest(ctx context.Context, tr core.TargetRequest, rawURL string) (*http.Request, error) {
	var body *bytes.Buffer
	if tr.Body != "" {
		body = bytes.NewBufferString(tr.Body)
	} else {
		body = bytes.NewBuffer(nil)
	}
	req, err := http.NewRequestWithContext(ctx, tr.Method, rawURL, body)
	if err != nil {
		return nil, err
	}
	for k, vals := range tr.Headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	if tr.Body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func baseline(ctx context.Context, tr core.TargetRequest, rm *request.Manager) (int, string, error) {
	req, err := buildRequest(ctx, tr, tr.URL)
	if err != nil {
		return 0, "", err
	}
	res, err := rm.Do(ctx, req)
	if err != nil {
		return 0, "", err
	}
	return res.Response.StatusCode, string(res.Body), nil
}

func paramKeys(u *url.URL) []string {
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		keys = append(keys, "q")
	}
	sort.Strings(keys)
	return keys
}

func mutateQuery(rawURL, key, payload string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(key, payload)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func containsAny(text string, patterns []string) (bool, string) {
	lower := strings.ToLower(text)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true, p
		}
	}
	return false, ""
}

func normalizeText(in string) string {
	if in == "" {
		return ""
	}
	return strings.ToLower(strings.Join(strings.Fields(in), " "))
}

func roughSimilarity(a, b string) float64 {
	na := normalizeText(a)
	nb := normalizeText(b)
	if na == "" && nb == "" {
		return 1
	}
	if na == "" || nb == "" {
		return 0
	}
	maxLen := len(na)
	if len(nb) > maxLen {
		maxLen = len(nb)
	}
	if maxLen == 0 {
		return 1
	}
	minLen := len(na)
	if len(nb) < minLen {
		minLen = len(nb)
	}
	matches := 0
	for i := 0; i < minLen; i++ {
		if na[i] == nb[i] {
			matches++
		}
	}
	return float64(matches) / float64(maxLen)
}

func buildFinding(module, severity, title, desc, endpoint, method, evidence, rec string) core.Finding {
	return buildFindingWithFullEvid(module, severity, title, desc, endpoint, method, evidence, rec, "", "")
}

func buildFindingWithFullEvid(module, severity, title, desc, endpoint, method, evidence, rec, rawReq, rawResp string) core.Finding {
	return core.Finding{
		Module:         module,
		Severity:       severity,
		Title:          title,
		Description:    desc,
		Endpoint:       endpoint,
		Method:         method,
		Evidence:       evidence,
		Recommendation: rec,
		RawRequest:     rawReq,
		RawResponse:    rawResp,
		Timestamp:      time.Now().UTC(),
	}
}
