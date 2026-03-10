package scanners

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"scannn3d/internal/core"
	"scannn3d/internal/request"

	"gopkg.in/yaml.v3"
)

type Template struct {
	ID   string       `yaml:"id"`
	Info TemplateInfo `yaml:"info"`
	HTTP []HTTPStep   `yaml:"http"`
}

type TemplateInfo struct {
	Name           string `yaml:"name"`
	Severity       string `yaml:"severity"`
	Description    string `yaml:"description"`
	Recommendation string `yaml:"recommendation"`
}

type HTTPStep struct {
	Method              string    `yaml:"method"`
	Payloads            []string  `yaml:"payloads"`
	ParameterCandidates []string  `yaml:"parameters"`
	MutatePath          bool      `yaml:"mutate_path"`
	Matchers            []Matcher `yaml:"matchers"`
}

type Matcher struct {
	Type     string   `yaml:"type"` // word, regex
	Part     string   `yaml:"part"` // body, header, status
	Words    []string `yaml:"words"`
	Negative bool     `yaml:"negative"`
}

type TemplateScanner struct {
	template Template
}

func (s *TemplateScanner) Name() string { return s.template.ID }

func (s *TemplateScanner) Scan(ctx context.Context, tr core.TargetRequest, rm *request.Manager) ([]core.Finding, error) {
	findings := make([]core.Finding, 0)

	for _, step := range s.template.HTTP {
		if step.MutatePath {
			pathMutations := MutatePathIDs(tr.URL)
			for _, mURL := range pathMutations {
				req, err := buildRequest(ctx, tr, mURL)
				if err != nil {
					continue
				}
				res, err := rm.Do(ctx, req)
				if err != nil {
					continue
				}
				if s.match(res, step.Matchers) {
					findings = append(findings, core.Finding{
						Module:         s.Name(),
						Severity:       s.template.Info.Severity,
						Title:          s.template.Info.Name,
						Description:    s.template.Info.Description,
						Endpoint:       mURL,
						Method:         tr.Method,
						Evidence:       "Path ID mutation matched template criteria.",
						Recommendation: s.template.Info.Recommendation,
						RawRequest:     res.RawRequest,
						RawResponse:    res.RawResponse,
						Timestamp:      time.Now(),
					})
				}
			}
		}

		if len(step.Payloads) > 0 {
			// Mutation-based scan
			u, err := url.Parse(tr.URL)
			if err != nil {
				continue
			}
			keys := paramKeys(u)
			for _, key := range keys {
				if len(step.ParameterCandidates) > 0 {
					matched := false
					for _, c := range step.ParameterCandidates {
						if strings.Contains(strings.ToLower(key), strings.ToLower(c)) {
							matched = true
							break
						}
					}
					if !matched {
						continue
					}
				}
				for _, payload := range step.Payloads {
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
					if s.match(res, step.Matchers) {
						findings = append(findings, core.Finding{
							Module:         s.Name(),
							Severity:       s.template.Info.Severity,
							Title:          s.template.Info.Name,
							Description:    s.template.Info.Description,
							Endpoint:       mURL,
							Method:         tr.Method,
							Evidence:       fmt.Sprintf("Matched payload %q in param %s", payload, key),
							Recommendation: s.template.Info.Recommendation,
							RawRequest:     res.RawRequest,
							RawResponse:    res.RawResponse,
							Timestamp:      time.Now(),
						})
					}
				}
			}
		} else if !step.MutatePath {
			// Single request scan
			req, err := buildRequest(ctx, tr, tr.URL)
			if err != nil {
				continue
			}
			res, err := rm.Do(ctx, req)
			if err != nil {
				continue
			}
			if s.match(res, step.Matchers) {
				findings = append(findings, core.Finding{
					Module:         s.Name(),
					Severity:       s.template.Info.Severity,
					Title:          s.template.Info.Name,
					Description:    s.template.Info.Description,
					Endpoint:       tr.URL,
					Method:         tr.Method,
					Evidence:       "Template match criteria satisfied.",
					Recommendation: s.template.Info.Recommendation,
					RawRequest:     res.RawRequest,
					RawResponse:    res.RawResponse,
					Timestamp:      time.Now(),
				})
			}
		}
	}

	return findings, nil
}

func (s *TemplateScanner) match(res *request.Result, matchers []Matcher) bool {
	if len(matchers) == 0 {
		return false
	}
	for _, m := range matchers {
		var content string
		switch m.Part {
		case "body":
			content = string(res.Body)
		case "header":
			// Serialize headers for word matching
			var hStr strings.Builder
			for k, v := range res.Response.Header {
				hStr.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ",")))
			}
			content = hStr.String()
		case "status":
			content = fmt.Sprintf("%d", res.Response.StatusCode)
		}

		matched := false
		if m.Type == "word" {
			for _, w := range m.Words {
				if strings.Contains(content, w) {
					matched = true
					break
				}
			}
		}

		if m.Negative {
			matched = !matched
		}
		if !matched {
			return false
		}
	}
	return true
}

func LoadTemplates(dir string, logger *slog.Logger) ([]core.Scanner, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	scanners := make([]core.Scanner, 0)
	for _, f := range files {
		if !f.IsDir() && (strings.HasSuffix(f.Name(), ".yaml") || strings.HasSuffix(f.Name(), ".yml")) {
			path := filepath.Join(dir, f.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				logger.Warn("template_load_failed", "path", path, "err", err)
				continue
			}
			var t Template
			if err := yaml.Unmarshal(data, &t); err != nil {
				logger.Warn("template_parse_failed", "path", path, "err", err)
				continue
			}
			scanners = append(scanners, &TemplateScanner{template: t})
		}
	}
	return scanners, nil
}
