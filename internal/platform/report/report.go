package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"scannn3d/internal/platform/storage"
)

func SaveJSON(dir string, bundle storage.ScanBundle) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "platform-report.json")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bundle); err != nil {
		return "", err
	}
	return path, nil
}

func SaveHTML(dir string, bundle storage.ScanBundle) (string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "platform-report.html")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	t := template.Must(template.New("r").Parse(htmlTpl))
	if err := t.Execute(f, bundle); err != nil {
		return "", fmt.Errorf("render html: %w", err)
	}
	return path, nil
}

const htmlTpl = `<!doctype html>
<html><head><meta charset="utf-8"><title>Platform Report</title>
<style>body{font-family:Arial,sans-serif;margin:24px;background:#f5f7fb} .card{background:#fff;padding:14px;border-radius:8px;margin-bottom:12px} code{background:#edf2f7;padding:2px 6px;border-radius:4px} table{border-collapse:collapse;width:100%;} th,td{border:1px solid #e2e8f0;padding:6px 8px;text-align:left;} th{background:#f1f5f9}</style></head>
<body>
<div class="card"><h1>Security Platform Report</h1><p><b>Target:</b> {{.Target.Address}}</p><p><b>Scan:</b> {{.Scan.ID}} ({{.Scan.Mode}} / {{.Scan.Status}})</p></div>

<div class="card"><h2>Etapas do Scan</h2>{{if .StepResults}}<table><thead><tr><th>Etapa</th><th>Status</th><th>Resumo</th><th>Severidade</th></tr></thead><tbody>{{range .StepResults}}<tr><td>{{.Name}}</td><td>{{.Status}}</td><td>{{.Summary}}</td><td>{{.Severity}}</td></tr>{{end}}</tbody></table>{{else}}<p>Nenhuma etapa registrada.</p>{{end}}</div>

<div class="card"><h2>Applications ({{len .Applications}})</h2>{{if .Applications}}<table><thead><tr><th>Base URL</th><th>Tipo</th><th>Framework/Stack</th></tr></thead><tbody>{{range .Applications}}<tr><td>{{.BaseURL}}</td><td>{{.AppType}}</td><td>{{.Framework}}</td></tr>{{end}}</tbody></table>{{else}}<p>Nenhuma aplicacao registrada.</p>{{end}}</div>

<div class="card"><h2>Services / Ports ({{len .Services}})</h2>{{if .Services}}<table><thead><tr><th>Porta</th><th>Protocolo</th><th>Servico</th><th>Banner</th></tr></thead><tbody>{{range .Services}}<tr><td>{{.Port}}</td><td>{{.Protocol}}</td><td>{{.Name}}</td><td>{{.Banner}}</td></tr>{{end}}</tbody></table>{{else}}<p>Nenhum servico identificado.</p>{{end}}</div>

<div class="card"><h2>Vulnerabilities ({{len .Vulnerabilities}})</h2>{{if .Vulnerabilities}}<table><thead><tr><th>Sev</th><th>CVSS</th><th>Titulo</th><th>Evidence</th></tr></thead><tbody>{{range .Vulnerabilities}}<tr><td>{{.Severity}}</td><td>{{printf "%.1f" .CVSS}}</td><td>{{.Title}}</td><td><code>{{.Evidence}}</code></td></tr>{{end}}</tbody></table>{{else}}<p>Nenhuma vulnerabilidade registrada.</p>{{end}}</div>

<div class="card"><h2>Attack Chain</h2>{{if .AttackChain.Steps}}{{range .AttackChain.Steps}}<p><b>{{.Step}}.</b> {{.Title}} ({{.Confidence}})<br>{{.Description}}</p>{{end}}{{else}}<p>Nenhuma cadeia montada.</p>{{end}}</div>
</body></html>`
