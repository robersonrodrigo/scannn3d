package discovery

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"scannn3d/internal/config"
	"scannn3d/internal/request"
)

func BuildTargets(ctx context.Context, cfg *config.Config, rm *request.Manager, logger *slog.Logger) ([]string, error) {
	seen := map[string]struct{}{}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		seen[raw] = struct{}{}
	}

	base, err := url.Parse(cfg.Target)
	if err != nil {
		return nil, err
	}

	for _, ep := range cfg.Endpoints {
		u, err := resolve(base, ep)
		if err == nil {
			add(u)
		}
	}

	if strings.TrimSpace(cfg.OpenAPIFile) != "" {
		routes, err := ParseOpenAPI(cfg.OpenAPIFile)
		if err != nil {
			return nil, err
		}
		for _, r := range routes {
			u, err := resolve(base, r)
			if err == nil {
				add(u)
			}
		}
		logger.Info("discovery_openapi_loaded", "file", cfg.OpenAPIFile, "count", len(routes))
	}

	if strings.TrimSpace(cfg.PostmanFile) != "" {
		routes, err := ParsePostman(cfg.PostmanFile)
		if err != nil {
			return nil, err
		}
		for _, r := range routes {
			u, err := resolve(base, r)
			if err == nil {
				add(u)
			}
		}
		logger.Info("discovery_postman_loaded", "file", cfg.PostmanFile, "count", len(routes))
	}

	if cfg.Crawl {
		seeds := make([]string, 0, len(seen))
		for u := range seen {
			seeds = append(seeds, u)
		}
		if len(seeds) == 0 {
			seeds = append(seeds, cfg.Target)
		}
		crawlURLs, err := Crawl(ctx, rm, logger, seeds, cfg.CrawlDepth)
		if err != nil {
			return nil, err
		}
		for _, u := range crawlURLs {
			add(u)
		}
		logger.Info("discovery_crawl_completed", "count", len(crawlURLs), "depth", cfg.CrawlDepth)
	}

	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	sort.Strings(out)
	return out, nil
}

func resolve(base *url.URL, endpoint string) (string, error) {
	epURL, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return "", err
	}
	if epURL.IsAbs() {
		return epURL.String(), nil
	}
	u := *base
	if strings.TrimSpace(epURL.Path) != "" {
		u.Path = joinPath(base.Path, epURL.Path)
	}
	u.RawQuery = epURL.RawQuery
	return u.String(), nil
}

func joinPath(basePath string, p string) string {
	if strings.HasSuffix(basePath, "/") {
		basePath = strings.TrimSuffix(basePath, "/")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if basePath == "" {
		return p
	}
	return basePath + p
}

func BuildRequest(method string, rawURL string, headers map[string]string, body string) *http.Request {
	_ = body
	req, _ := http.NewRequest(method, rawURL, nil)
	if req != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
	return req
}
