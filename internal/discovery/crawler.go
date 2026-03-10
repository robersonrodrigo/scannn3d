package discovery

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"scannn3d/internal/request"
)

var linkRe = regexp.MustCompile(`(?i)(?:href|src)=["']([^"'#]+)["']`)

func Crawl(ctx context.Context, rm *request.Manager, logger *slog.Logger, seeds []string, maxDepth int) ([]string, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}
	type node struct {
		url   string
		depth int
	}

	visited := map[string]struct{}{}
	queue := make([]node, 0, len(seeds))
	for _, s := range seeds {
		s = strings.TrimSpace(s)
		if s != "" {
			queue = append(queue, node{url: s, depth: 0})
		}
	}

	found := map[string]struct{}{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if _, ok := visited[cur.url]; ok {
			continue
		}
		visited[cur.url] = struct{}{}
		found[cur.url] = struct{}{}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cur.url, nil)
		if err != nil {
			continue
		}
		res, err := rm.Do(ctx, req)
		if err != nil {
			continue
		}
		if cur.depth >= maxDepth {
			continue
		}
		if !strings.Contains(strings.ToLower(res.Response.Header.Get("Content-Type")), "text/html") {
			continue
		}

		links, err := extractLinks(cur.url, string(res.Body))
		if err != nil {
			logger.Debug("crawl_extract_failed", "url", cur.url, "err", err)
			continue
		}
		for _, l := range links {
			if _, ok := visited[l]; ok {
				continue
			}
			queue = append(queue, node{url: l, depth: cur.depth + 1})
		}
	}

	out := make([]string, 0, len(found))
	for u := range found {
		out = append(out, u)
	}
	sort.Strings(out)
	return out, nil
}

func extractLinks(baseURL string, htmlBody string) ([]string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	matches := linkRe.FindAllStringSubmatch(htmlBody, -1)
	out := make([]string, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(strings.ToLower(raw), "javascript:") || strings.HasPrefix(raw, "mailto:") {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(u)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			continue
		}
		r := resolved.String()
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out, nil
}
