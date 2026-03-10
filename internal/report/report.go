package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"time"

	"scannn3d/internal/core"
)

type Summary struct {
	Total        int            `json:"total"`
	BySeverity   map[string]int `json:"by_severity"`
	ByModule     map[string]int `json:"by_module"`
	GeneratedAt  time.Time      `json:"generated_at"`
	Target       string         `json:"target"`
	ElapsedMilli int64          `json:"elapsed_ms"`
}

type Report struct {
	Summary  Summary        `json:"summary"`
	Findings []core.Finding `json:"findings"`
}

func Build(findings []core.Finding, target string, elapsed time.Duration) Report {
	s := Summary{
		Total:        len(findings),
		BySeverity:   map[string]int{},
		ByModule:     map[string]int{},
		GeneratedAt:  time.Now().UTC(),
		Target:       target,
		ElapsedMilli: elapsed.Milliseconds(),
	}
	for _, f := range findings {
		s.BySeverity[f.Severity]++
		s.ByModule[f.Module]++
	}
	return Report{Summary: s, Findings: findings}
}

func SaveJSON(dir string, rep Report) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "report.json")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return "", err
	}
	return path, nil
}

func SaveHTML(dir string, rep Report) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "report.html")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	ordered := append([]core.Finding(nil), rep.Findings...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Severity == ordered[j].Severity {
			return ordered[i].Module < ordered[j].Module
		}
		return severityRank(ordered[i].Severity) < severityRank(ordered[j].Severity)
	})

	data := struct {
		Summary  Summary
		Findings []core.Finding
	}{Summary: rep.Summary, Findings: ordered}

	tpl := template.Must(template.New("report").Parse(htmlTemplate))
	if err := tpl.Execute(f, data); err != nil {
		return "", fmt.Errorf("render html: %w", err)
	}
	return path, nil
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

const htmlTemplate = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>scannn3d report</title>
<style>
body { font-family: -apple-system, Segoe UI, sans-serif; margin: 24px; background: #f7f7f9; color: #1f2937; }
.card { background: white; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; }
.high { background:#fee2e2; color:#991b1b; }
.medium { background:#fef3c7; color:#92400e; }
.low { background:#dbeafe; color:#1e3a8a; }
code { background:#f3f4f6; padding:1px 5px; border-radius:4px; }
</style>
</head>
<body>
<div class="card">
<h1>scannn3d report</h1>
<p><strong>Target:</strong> {{.Summary.Target}}</p>
<p><strong>Generated:</strong> {{.Summary.GeneratedAt}}</p>
<p><strong>Total findings:</strong> {{.Summary.Total}}</p>
<p><strong>Elapsed:</strong> {{.Summary.ElapsedMilli}} ms</p>
</div>
{{range .Findings}}
<div class="card">
<h3>{{.Title}} <span class="badge {{.Severity}}">{{.Severity}}</span></h3>
<p><strong>Module:</strong> {{.Module}} | <strong>Method:</strong> {{.Method}}</p>
<p><strong>Endpoint:</strong> <code>{{.Endpoint}}</code></p>
<p>{{.Description}}</p>
<p><strong>Evidence:</strong> <code>{{.Evidence}}</code></p>
<p><strong>Recommendation:</strong> {{.Recommendation}}</p>
</div>
{{end}}
</body>
</html>`
