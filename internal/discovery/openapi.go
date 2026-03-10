package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type openAPIDoc struct {
	Paths map[string]json.RawMessage `json:"paths"`
}

func ParseOpenAPI(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read openapi: %w", err)
	}

	var doc openAPIDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse openapi as json: %w", err)
	}
	out := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}
