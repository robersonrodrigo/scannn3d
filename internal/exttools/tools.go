package extools

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"scannn3d/internal/config"
	"scannn3d/internal/core"
)

type Result struct {
	Tool      string   `json:"tool"`
	Status    string   `json:"status"`
	Artifact  string   `json:"artifact,omitempty"`
	Message   string   `json:"message,omitempty"`
	Profile   string   `json:"profile,omitempty"`
	Command   []string `json:"command,omitempty"`
	ElapsedMS int64    `json:"elapsed_ms"`
}

type toolSpec struct {
	Name string
	Bins []string
	Args func(cfg *config.Config, outDir string, bin string) ([]string, error)
}

func Run(ctx context.Context, cfg *config.Config, outDir string, logger *slog.Logger, onUpdate func(Result)) ([]core.Finding, []Result, error) {
	selected := normalizeSelection(cfg.ExternalTools, cfg.DirsearchEnabled)
	if len(selected) == 0 {
		return nil, nil, nil
	}

	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return nil, nil, err
	}

	specs := allSpecs()
	all := make([]core.Finding, 0, len(selected)*2)
	results := make([]Result, 0, len(selected))
	for _, name := range selected {
		spec, ok := specs[name]
		if !ok {
			all = append(all, finding("external-"+name, "low", "External Tool Not Supported", cfg.Target, "unknown tool"))
			r := Result{Tool: name, Status: "unsupported", Message: "unknown tool"}
			if onUpdate != nil {
				onUpdate(r)
			}
			results = append(results, r)
			continue
		}
		running := Result{Tool: spec.Name, Status: "running", Message: "starting"}
		if onUpdate != nil {
			onUpdate(running)
		}
		f, r := runOne(ctx, cfg, outDir, logger, spec)
		all = append(all, f...)
		if onUpdate != nil {
			onUpdate(r)
		}
		results = append(results, r)
	}
	return all, results, nil
}

func runOne(ctx context.Context, cfg *config.Config, outDir string, logger *slog.Logger, spec toolSpec) ([]core.Finding, Result) {
	bin, err := resolveBin(spec.Bins)
	if err != nil {
		return []core.Finding{finding("external-"+spec.Name, "low", "Tool Not Installed", cfg.Target, err.Error())}, Result{
			Tool: spec.Name, Status: "not_installed", Message: err.Error(),
		}
	}

	profile := ""
	var args []string
	if spec.Name == "dirsearch" {
		args, profile, err = buildDirsearchArgs(cfg, outDir)
	} else {
		args, err = spec.Args(cfg, outDir, filepath.Base(bin))
	}
	if err != nil {
		return []core.Finding{finding("external-"+spec.Name, "low", "Tool Configuration Error", cfg.Target, err.Error())}, Result{
			Tool: spec.Name, Status: "config_error", Message: err.Error(), Profile: profile,
		}
	}

	timeout := cfg.ExternalTimeout
	if timeout <= 0 {
		timeout = 8 * time.Minute
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(tctx, bin, args...)
	start := time.Now()
	output, runErr := cmd.CombinedOutput()
	elapsed := time.Since(start).Milliseconds()
	artifact := filepath.Join(outDir, spec.Name+".log")
	_ = os.WriteFile(artifact, output, 0o640)

	command := append([]string{filepath.Base(bin)}, args...)
	if tctx.Err() == context.DeadlineExceeded {
		return []core.Finding{finding("external-"+spec.Name, "medium", "Tool Timeout", cfg.Target, fmt.Sprintf("timeout=%s artifact=%s", timeout.String(), artifact))}, Result{
			Tool: spec.Name, Status: "timeout", Artifact: artifact, ElapsedMS: elapsed, Message: "execution timed out", Profile: profile, Command: command,
		}
	}

	if runErr != nil {
		logger.Warn("external_tool_failed", "tool", spec.Name, "err", runErr)
		finds := append([]core.Finding{finding("external-"+spec.Name, "low", "Tool Execution Failed", cfg.Target, fmt.Sprintf("error=%v artifact=%s", runErr, artifact))}, parseFindings(spec.Name, cfg.Target, outDir, output)...)
		return finds, Result{
			Tool: spec.Name, Status: "failed", Artifact: artifact, ElapsedMS: elapsed, Message: runErr.Error(), Profile: profile, Command: command,
		}
	}

	finds := append([]core.Finding{finding("external-"+spec.Name, "low", "Tool Executed", cfg.Target, fmt.Sprintf("elapsed_ms=%d artifact=%s", elapsed, artifact))}, parseFindings(spec.Name, cfg.Target, outDir, output)...)
	return finds, Result{
		Tool: spec.Name, Status: "completed", Artifact: artifact, ElapsedMS: elapsed, Message: "ok", Profile: profile, Command: command,
	}
}

func allSpecs() map[string]toolSpec {
	return map[string]toolSpec{
		"subfinder": {
			Name: "subfinder",
			Bins: []string{"subfinder"},
			Args: func(cfg *config.Config, outDir string, _ string) ([]string, error) {
				h, err := hostFromTarget(cfg.Target)
				if err != nil {
					return nil, err
				}
				return []string{"-silent", "-d", h, "-o", filepath.Join(outDir, "subfinder.txt")}, nil
			},
		},
		"dirsearch": {
			Name: "dirsearch",
			Bins: []string{"dirsearch", "dirsearch.py"},
			Args: func(cfg *config.Config, outDir string, _ string) ([]string, error) {
				args, _, err := buildDirsearchArgs(cfg, outDir)
				return args, err
			},
		},
		"owasp-zap": {
			Name: "owasp-zap",
			Bins: []string{"zap-baseline.py", "zaproxy"},
			Args: func(cfg *config.Config, outDir string, bin string) ([]string, error) {
				if strings.HasSuffix(strings.ToLower(bin), ".py") {
					return []string{"-t", cfg.Target, "-J", filepath.Join(outDir, "owasp-zap.json"), "-r", filepath.Join(outDir, "owasp-zap.html")}, nil
				}
				return []string{"-cmd", "-quickurl", cfg.Target, "-quickout", filepath.Join(outDir, "owasp-zap.txt")}, nil
			},
		},
		"wapiti": {
			Name: "wapiti",
			Bins: []string{"wapiti"},
			Args: func(cfg *config.Config, outDir string, _ string) ([]string, error) {
				return []string{"-u", cfg.Target, "-f", "json", "-o", filepath.Join(outDir, "wapiti.json")}, nil
			},
		},
		"sqlmap": {
			Name: "sqlmap",
			Bins: []string{"sqlmap"},
			Args: func(cfg *config.Config, outDir string, _ string) ([]string, error) {
				return []string{"-u", cfg.Target, "--batch", "--crawl=1", "--output-dir", filepath.Join(outDir, "sqlmap")}, nil
			},
		},
		"wpscan": {
			Name: "wpscan",
			Bins: []string{"wpscan"},
			Args: func(cfg *config.Config, outDir string, _ string) ([]string, error) {
				return []string{"--url", cfg.Target, "--format", "json", "--output", filepath.Join(outDir, "wpscan.json"), "--no-update"}, nil
			},
		},
		"nmap": {
			Name: "nmap",
			Bins: []string{"nmap"},
			Args: func(cfg *config.Config, outDir string, _ string) ([]string, error) {
				h, err := hostFromTarget(cfg.Target)
				if err != nil {
					return nil, err
				}
				return []string{"-sV", "--script", "vuln", "-oX", filepath.Join(outDir, "nmap.xml"), h}, nil
			},
		},
		"metasploit": {
			Name: "metasploit",
			Bins: []string{"msfconsole"},
			Args: func(cfg *config.Config, outDir string, _ string) ([]string, error) {
				h, err := hostFromTarget(cfg.Target)
				if err != nil {
					return nil, err
				}
				script := fmt.Sprintf("use auxiliary/scanner/http/http_version; set RHOSTS %s; run; exit", h)
				return []string{"-q", "-x", script}, nil
			},
		},
		"nikto": {
			Name: "nikto",
			Bins: []string{"nikto"},
			Args: func(cfg *config.Config, outDir string, _ string) ([]string, error) {
				return []string{"-h", cfg.Target, "-Format", "json", "-output", filepath.Join(outDir, "nikto.json")}, nil
			},
		},
		"arachni": {
			Name: "arachni",
			Bins: []string{"arachni"},
			Args: func(cfg *config.Config, outDir string, _ string) ([]string, error) {
				return []string{cfg.Target, "--report-save-path", filepath.Join(outDir, "arachni.afr")}, nil
			},
		},
		"vega": {
			Name: "vega",
			Bins: []string{"vega", "vega-cli"},
			Args: func(cfg *config.Config, outDir string, _ string) ([]string, error) {
				return []string{"--help"}, nil
			},
		},
	}
}

func normalizeSelection(in []string, dirsearchEnabled bool) []string {
	if len(in) == 0 {
		return nil
	}
	catalog := []string{"subfinder", "dirsearch", "owasp-zap", "wapiti", "sqlmap", "wpscan", "nmap", "metasploit", "nikto", "arachni", "vega"}
	if len(in) == 1 && strings.EqualFold(strings.TrimSpace(in[0]), "all") {
		if !dirsearchEnabled {
			return filterOut(catalog, "dirsearch")
		}
		return catalog
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, name := range in {
		n := strings.ToLower(strings.TrimSpace(name))
		if n == "" {
			continue
		}
		if !dirsearchEnabled && n == "dirsearch" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func filterOut(in []string, v string) []string {
	out := make([]string, 0, len(in))
	for _, it := range in {
		if it != v {
			out = append(out, it)
		}
	}
	return out
}

func resolveBin(candidates []string) (string, error) {
	for _, b := range candidates {
		if p, err := exec.LookPath(b); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("binary not found: %s", strings.Join(candidates, " or "))
}

func finding(module, severity, title, endpoint, evidence string) core.Finding {
	return core.Finding{
		Module:         module,
		Severity:       severity,
		Title:          title,
		Description:    "External integration result.",
		Endpoint:       endpoint,
		Method:         "EXTERNAL",
		Evidence:       evidence,
		Recommendation: "Review generated artifact and validate findings before remediation.",
		Timestamp:      time.Now().UTC(),
	}
}

func hostFromTarget(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	h := strings.TrimSpace(u.Hostname())
	if h == "" {
		return "", fmt.Errorf("target host is empty")
	}
	return h, nil
}

func parseFindings(tool string, target string, outDir string, output []byte) []core.Finding {
	switch tool {
	case "subfinder":
		return parseSubfinder(target, outDir, output)
	case "dirsearch":
		return parseDirsearch(target, outDir, output)
	case "owasp-zap":
		return parseZAP(target, outDir, output)
	case "wapiti":
		return parseWapiti(target, outDir, output)
	case "sqlmap":
		return parseByKeywords("external-sqlmap", target, output, []string{"injection point", "vulnerable", "parameter"}, "Potential SQL injection indicators from sqlmap output")
	case "wpscan":
		return parseWPSCan(target, outDir, output)
	case "nmap":
		return parseNmap(target, outDir, output)
	case "nikto":
		return parseByKeywords("external-nikto", target, output, []string{"OSVDB", "vulnerable", "misconfiguration", "outdated"}, "Potential web server weakness indicators from nikto output")
	case "arachni":
		return parseByKeywords("external-arachni", target, output, []string{"issue", "vulnerability", "xss", "sql injection"}, "Potential web vulnerabilities indicated by Arachni output")
	case "metasploit":
		return parseByKeywords("external-metasploit", target, output, []string{"vulnerable", "exploit", "matched"}, "Potential exploitation signal from Metasploit module output")
	case "vega":
		return parseByKeywords("external-vega", target, output, []string{"xss", "sql injection", "vulnerability"}, "Potential web vulnerability indicators from Vega output")
	default:
		return nil
	}
}

func parseSubfinder(target, outDir string, output []byte) []core.Finding {
	b, err := os.ReadFile(filepath.Join(outDir, "subfinder.txt"))
	if err != nil {
		b = output
	}
	lines := strings.Split(string(b), "\n")
	count := 0
	for _, ln := range lines {
		if strings.TrimSpace(ln) != "" {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	return []core.Finding{{
		Module:         "external-subfinder",
		Severity:       "low",
		Title:          "Subdomain Surface Expanded",
		Description:    "Subfinder identified additional subdomains for the target scope.",
		Endpoint:       target,
		Method:         "EXTERNAL",
		Evidence:       fmt.Sprintf("subdomains_discovered=%d", count),
		Recommendation: "Validate discovered subdomains, ownership, and exposure before active testing.",
		Timestamp:      time.Now().UTC(),
	}}
}

func parseByKeywords(module, target string, output []byte, keys []string, desc string) []core.Finding {
	text := strings.ToLower(string(output))
	for _, k := range keys {
		if strings.Contains(text, strings.ToLower(k)) {
			return []core.Finding{{
				Module:         module,
				Severity:       "medium",
				Title:          "External Tool Alert Pattern",
				Description:    desc,
				Endpoint:       target,
				Method:         "EXTERNAL",
				Evidence:       "keyword=" + k,
				Recommendation: "Validate externally reported issue and correlate with in-app findings.",
				Timestamp:      time.Now().UTC(),
			}}
		}
	}
	return nil
}

func parseDirsearch(target, outDir string, output []byte) []core.Finding {
	b, err := os.ReadFile(filepath.Join(outDir, "dirsearch.json"))
	if err != nil {
		b = output
	}

	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return parseByKeywords("external-dirsearch", target, output, []string{"admin", ".env", "backup", "config", "secret"}, "Potential sensitive path exposed by directory bruteforce")
	}

	results := extractDirsearchResults(raw)
	if len(results) == 0 {
		return nil
	}
	out := make([]core.Finding, 0, minInt(25, len(results)))
	for _, r := range results {
		endpoint := firstNonEmpty(r.URL, target)
		sev := severityFromPath(r.Path)
		out = append(out, core.Finding{
			Module:         "external-dirsearch",
			Severity:       sev,
			Title:          "Dirsearch Exposed Path",
			Description:    "Path discovered by dirsearch that may expose sensitive surface.",
			Endpoint:       endpoint,
			Method:         "EXTERNAL",
			Evidence:       fmt.Sprintf("status=%d path=%s", r.Status, r.Path),
			Recommendation: "Review exposed route and enforce authorization, hardening, and disable unnecessary resources.",
			Timestamp:      time.Now().UTC(),
		})
		if len(out) >= 25 {
			break
		}
	}
	return out
}

type dirsearchEntry struct {
	Path   string
	URL    string
	Status int
}

func extractDirsearchResults(raw map[string]any) []dirsearchEntry {
	out := make([]dirsearchEntry, 0, 32)
	visit := func(entry map[string]any) {
		p, _ := entry["path"].(string)
		u, _ := entry["url"].(string)
		status := intFromAny(entry["status"])
		if p == "" && u == "" {
			return
		}
		if status == 0 {
			status = intFromAny(entry["status_code"])
		}
		out = append(out, dirsearchEntry{Path: p, URL: u, Status: status})
	}

	for _, key := range []string{"results", "data", "entries"} {
		arr, ok := raw[key].([]any)
		if !ok {
			continue
		}
		for _, it := range arr {
			if m, ok := it.(map[string]any); ok {
				visit(m)
			}
		}
	}

	if len(out) == 0 {
		for _, v := range raw {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			arr, ok := m["results"].([]any)
			if !ok {
				continue
			}
			for _, it := range arr {
				if mm, ok := it.(map[string]any); ok {
					visit(mm)
				}
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Status == out[j].Status {
			return out[i].Path < out[j].Path
		}
		return out[i].Status < out[j].Status
	})
	return out
}

func intFromAny(v any) int {
	switch vv := v.(type) {
	case float64:
		return int(vv)
	case int:
		return vv
	case string:
		var i int
		_, _ = fmt.Sscanf(vv, "%d", &i)
		return i
	default:
		return 0
	}
}

func severityFromPath(p string) string {
	l := strings.ToLower(p)
	high := []string{".env", "backup", "dump", "sql", "config", "secret", "key", ".git", "admin"}
	medium := []string{"staging", "dev", "test", "old", "tmp", "debug"}
	for _, x := range high {
		if strings.Contains(l, x) {
			return "high"
		}
	}
	for _, x := range medium {
		if strings.Contains(l, x) {
			return "medium"
		}
	}
	return "low"
}

func parseZAP(target, outDir string, output []byte) []core.Finding {
	b, err := os.ReadFile(filepath.Join(outDir, "owasp-zap.json"))
	if err != nil {
		b = output
	}
	var doc struct {
		Site []struct {
			Alerts []struct {
				RiskDesc string `json:"riskdesc"`
				Alert    string `json:"alert"`
				URI      string `json:"uri"`
			} `json:"alerts"`
		} `json:"site"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil
	}
	out := make([]core.Finding, 0, 5)
	for _, s := range doc.Site {
		for _, a := range s.Alerts {
			sev := "low"
			rl := strings.ToLower(a.RiskDesc)
			if strings.Contains(rl, "high") {
				sev = "high"
			} else if strings.Contains(rl, "medium") {
				sev = "medium"
			}
			out = append(out, core.Finding{
				Module:         "external-owasp-zap",
				Severity:       sev,
				Title:          "ZAP Alert: " + a.Alert,
				Description:    "Alert imported from OWASP ZAP baseline output.",
				Endpoint:       firstNonEmpty(a.URI, target),
				Method:         "EXTERNAL",
				Evidence:       a.RiskDesc,
				Recommendation: "Review ZAP evidence and validate exploitability.",
				Timestamp:      time.Now().UTC(),
			})
			if len(out) >= 25 {
				return out
			}
		}
	}
	return out
}

func parseWapiti(target, outDir string, output []byte) []core.Finding {
	b, err := os.ReadFile(filepath.Join(outDir, "wapiti.json"))
	if err != nil {
		b = output
	}
	var data map[string]any
	if err := json.Unmarshal(b, &data); err != nil {
		return nil
	}
	vulns, _ := data["vulnerabilities"].(map[string]any)
	out := make([]core.Finding, 0, 8)
	for kind, raw := range vulns {
		items, ok := raw.([]any)
		if !ok || len(items) == 0 {
			continue
		}
		out = append(out, core.Finding{
			Module:         "external-wapiti",
			Severity:       "medium",
			Title:          "Wapiti Vulnerability Group: " + kind,
			Description:    "Vulnerability group detected by Wapiti.",
			Endpoint:       target,
			Method:         "EXTERNAL",
			Evidence:       fmt.Sprintf("count=%d", len(items)),
			Recommendation: "Inspect Wapiti report entries and validate affected endpoints.",
			Timestamp:      time.Now().UTC(),
		})
	}
	return out
}

func parseWPSCan(target, outDir string, output []byte) []core.Finding {
	b, err := os.ReadFile(filepath.Join(outDir, "wpscan.json"))
	if err != nil {
		b = output
	}
	var data any
	if err := json.Unmarshal(b, &data); err != nil {
		return nil
	}
	count := countKey(data, "vulnerabilities")
	if count == 0 {
		return nil
	}
	return []core.Finding{{
		Module:         "external-wpscan",
		Severity:       "medium",
		Title:          "WPScan Reported Vulnerabilities",
		Description:    "WPScan found vulnerability entries in WordPress components.",
		Endpoint:       target,
		Method:         "EXTERNAL",
		Evidence:       fmt.Sprintf("vulnerability_entries=%d", count),
		Recommendation: "Patch vulnerable plugins/themes/core and remove unused components.",
		Timestamp:      time.Now().UTC(),
	}}
}

func parseNmap(target, outDir string, output []byte) []core.Finding {
	b, err := os.ReadFile(filepath.Join(outDir, "nmap.xml"))
	if err != nil {
		b = output
	}
	var report struct {
		Hosts []struct {
			Ports []struct {
				PortID string `xml:"portid,attr"`
				State  struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Scripts []struct {
					ID     string `xml:"id,attr"`
					Output string `xml:"output,attr"`
				} `xml:"script"`
			} `xml:"ports>port"`
		} `xml:"host"`
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&report); err != nil {
		return nil
	}
	out := make([]core.Finding, 0, 8)
	for _, h := range report.Hosts {
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			for _, s := range p.Scripts {
				if strings.Contains(strings.ToLower(s.Output), "vulnerable") {
					out = append(out, core.Finding{
						Module:         "external-nmap",
						Severity:       "medium",
						Title:          "Nmap NSE Vulnerability Indicator",
						Description:    "Nmap NSE script reported possible vulnerability.",
						Endpoint:       target,
						Method:         "EXTERNAL",
						Evidence:       fmt.Sprintf("port=%s script=%s", p.PortID, s.ID),
						Recommendation: "Review Nmap XML report and validate service exposure.",
						Timestamp:      time.Now().UTC(),
					})
				}
			}
		}
	}
	return out
}

func countKey(node any, key string) int {
	switch v := node.(type) {
	case map[string]any:
		n := 0
		for k, vv := range v {
			if k == key {
				if arr, ok := vv.([]any); ok {
					n += len(arr)
				}
			}
			n += countKey(vv, key)
		}
		return n
	case []any:
		n := 0
		for _, vv := range v {
			n += countKey(vv, key)
		}
		return n
	default:
		return 0
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func buildDirsearchArgs(cfg *config.Config, outDir string) ([]string, string, error) {
	profile := strings.ToLower(strings.TrimSpace(cfg.DirsearchProfile))
	if profile == "" {
		profile = "auto"
	}
	if profile == "auto" {
		detected, _ := detectDirsearchProfile(cfg.Target, cfg.InsecureTLS)
		if detected != "" {
			profile = detected
		} else {
			profile = "generic-web"
		}
	}

	intensity := strings.ToLower(strings.TrimSpace(cfg.DirsearchIntensity))
	if intensity == "" {
		intensity = "balanced"
	}

	extensions := map[string]string{
		"generic-web":  "php,asp,aspx,jsp,js,txt,zip,bak,old",
		"api-rest":     "json,yaml,yml,txt",
		"spa":          "js,json,map,txt",
		"wordpress":    "php,txt,zip,bak",
		"drupal":       "php,txt,sql,tar,zip",
		"joomla":       "php,txt,sql,zip",
		"laravel":      "php,env,log,txt,zip",
		"django":       "py,txt,log,sqlite3,bak",
		"rails":        "rb,yml,log,sql,bak",
		"node-express": "js,json,env,log,bak",
	}
	prefixes := map[string]string{
		"api-rest":     "api,v1,v2,internal",
		"wordpress":    "wp-admin,wp-content,wp-includes",
		"drupal":       "sites,modules,themes",
		"joomla":       "administrator,components,modules,templates",
		"laravel":      "storage,bootstrap,vendor,public",
		"django":       "static,media,admin",
		"rails":        "assets,packs,rails,admin",
		"node-express": "api,admin,public",
	}

	threads := 22
	timeoutSec := 10
	if intensity == "conservative" {
		threads = 10
		timeoutSec = 8
	} else if intensity == "aggressive" {
		threads = 40
		timeoutSec = 15
	}

	ext := extensions[profile]
	if ext == "" {
		ext = extensions["generic-web"]
	}

	args := []string{
		"-u", cfg.Target,
		"-e", ext,
		"--threads", fmt.Sprintf("%d", threads),
		"--timeout", fmt.Sprintf("%d", timeoutSec),
		"--random-agent",
		"--exclude-status", "400,401,403,404,429,500,502,503",
		"--format", "json",
		"--output", filepath.Join(outDir, "dirsearch.json"),
	}
	if pfx := prefixes[profile]; pfx != "" {
		args = append(args, "--prefixes", pfx)
	}
	if profile == "spa" {
		args = append(args, "--exclude-extensions", "png,jpg,jpeg,gif,svg,woff,woff2")
	}
	return args, profile, nil
}

func detectDirsearchProfile(target string, insecureTLS bool) (string, []string) {
	u, err := url.Parse(target)
	if err != nil {
		return "", nil
	}
	evidence := []string{}
	pathLower := strings.ToLower(u.Path)
	if strings.Contains(pathLower, "/api") {
		evidence = append(evidence, "path_contains_api")
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecureTLS}
	client := &http.Client{Timeout: 6 * time.Second, Transport: tr}
	resp, err := client.Get(target)
	if err != nil {
		if strings.Contains(pathLower, "/api") {
			return "api-rest", evidence
		}
		return "generic-web", evidence
	}
	defer resp.Body.Close()

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	server := strings.ToLower(resp.Header.Get("Server"))
	xpb := strings.ToLower(resp.Header.Get("X-Powered-By"))
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	body := strings.ToLower(string(b))

	if strings.Contains(ct, "application/json") || strings.Contains(pathLower, "/api") || strings.Contains(body, "\"openapi\"") || strings.Contains(body, "swagger") {
		return "api-rest", append(evidence, "json_or_api_marker")
	}
	if strings.Contains(body, "wp-content") || strings.Contains(body, "wp-includes") {
		return "wordpress", append(evidence, "wordpress_marker")
	}
	if strings.Contains(body, "drupal-settings-json") || strings.Contains(body, "drupal") {
		return "drupal", append(evidence, "drupal_marker")
	}
	if strings.Contains(body, "joomla") {
		return "joomla", append(evidence, "joomla_marker")
	}
	if strings.Contains(xpb, "express") || strings.Contains(server, "express") {
		return "node-express", append(evidence, "express_header")
	}
	if strings.Contains(body, "laravel") || strings.Contains(body, "csrf-token") {
		return "laravel", append(evidence, "laravel_marker")
	}
	if strings.Contains(body, "csrfmiddlewaretoken") || strings.Contains(body, "django") {
		return "django", append(evidence, "django_marker")
	}
	if strings.Contains(body, "rails") || strings.Contains(body, "authenticity_token") {
		return "rails", append(evidence, "rails_marker")
	}
	if strings.Contains(body, "<script") && strings.Contains(body, "bundle") {
		return "spa", append(evidence, "spa_bundle_marker")
	}
	return "generic-web", evidence
}
