package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type postmanCollection struct {
	Item []postmanItem `json:"item"`
}

type postmanItem struct {
	Item    []postmanItem   `json:"item"`
	Request *postmanRequest `json:"request"`
}

type postmanRequest struct {
	URL any `json:"url"`
}

func ParsePostman(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read postman: %w", err)
	}
	var c postmanCollection
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse postman json: %w", err)
	}

	seen := map[string]struct{}{}
	walkPostman(c.Item, seen)

	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func walkPostman(items []postmanItem, seen map[string]struct{}) {
	for _, it := range items {
		if it.Request != nil {
			u := postmanURLToString(it.Request.URL)
			u = strings.TrimSpace(u)
			if u != "" {
				seen[u] = struct{}{}
			}
		}
		if len(it.Item) > 0 {
			walkPostman(it.Item, seen)
		}
	}
}

func postmanURLToString(v any) string {
	switch vv := v.(type) {
	case string:
		return vv
	case map[string]any:
		if raw, ok := vv["raw"].(string); ok {
			return raw
		}
		pathParts, _ := vv["path"].([]any)
		if len(pathParts) == 0 {
			return ""
		}
		parts := make([]string, 0, len(pathParts))
		for _, p := range pathParts {
			if s, ok := p.(string); ok {
				parts = append(parts, s)
			}
		}
		if len(parts) == 0 {
			return ""
		}
		return "/" + strings.Join(parts, "/")
	default:
		return ""
	}
}
