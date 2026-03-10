package orchestration

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"scannn3d/internal/platform/storage"
)

// wafw00fResult captures a lightweight WAF fingerprint outcome.
type wafw00fResult struct {
	Detected bool
	Name     string
	Raw      string
}

// whatwebResult captures detected technologies from whatweb.
type whatwebResult struct {
	Tech []string
	Raw  string
}

type wafw00fParsed struct {
	Detected bool
	Name     string
	Requests int
}

// runWafw00f executes wafw00f against a URL target.
func runWafw00f(ctx context.Context, targetURL, outDir string) (wafw00fResult, error) {
	bin, err := exec.LookPath("wafw00f")
	if err != nil {
		return wafw00fResult{}, fmt.Errorf("wafw00f not installed")
	}

	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return wafw00fResult{}, err
	}

	args := []string{"-a", targetURL}
	tctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(tctx, bin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err = cmd.Run()
	raw := buf.String()
	_ = os.WriteFile(filepath.Join(outDir, "wafw00f.log"), []byte(raw), 0o640)

	if tctx.Err() == context.DeadlineExceeded {
		return wafw00fResult{}, fmt.Errorf("wafw00f timeout")
	}
	if err != nil {
		return wafw00fResult{Raw: raw}, fmt.Errorf("wafw00f failed: %v", err)
	}

	parsed := parseWafw00f(raw)
	return wafw00fResult{Raw: raw, Detected: parsed.Detected, Name: parsed.Name}, nil
}

// runWhatweb executes whatweb and returns detected technologies.
func runWhatweb(ctx context.Context, targetURL, outDir string) (whatwebResult, error) {
	bin, err := exec.LookPath("whatweb")
	if err != nil {
		return whatwebResult{}, fmt.Errorf("whatweb not installed")
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return whatwebResult{}, err
	}
	args := []string{"--color=never", "--no-errors", targetURL}
	tctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(tctx, bin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err = cmd.Run()
	raw := buf.String()
	_ = os.WriteFile(filepath.Join(outDir, "whatweb.log"), []byte(raw), 0o640)
	if tctx.Err() == context.DeadlineExceeded {
		return whatwebResult{}, fmt.Errorf("whatweb timeout")
	}
	if err != nil {
		return whatwebResult{Raw: raw}, fmt.Errorf("whatweb failed: %v", err)
	}

	tech := parseWhatweb(raw)
	return whatwebResult{Tech: tech, Raw: raw}, nil
}

func parseWhatweb(raw string) []string {
	// Default whatweb output: "http://target [200 OK] Tech1[ver], Tech2"
	parts := strings.SplitN(raw, "]", 2)
	if len(parts) != 2 {
		return nil
	}
	tail := parts[1]
	tokens := strings.Split(tail, ",")
	out := make([]string, 0, len(tokens))
	for _, tk := range tokens {
		t := strings.TrimSpace(tk)
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return out
}

func parseWafw00f(raw string) wafw00fParsed {
	lines := strings.Split(raw, "\n")
	p := wafw00fParsed{}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "no waf detected") {
		p.Detected = false
	}
	for _, ln := range lines {
		ll := strings.ToLower(ln)
		if strings.Contains(ll, "behind") {
			p.Detected = true
			parts := strings.Split(ln, "behind")
			if len(parts) > 1 {
				name := strings.TrimSpace(parts[1])
				name = strings.Trim(name, ". !")
				p.Name = name
			}
		}
		if strings.Contains(ll, "requests:") {
			fields := strings.Fields(ll)
			for i, f := range fields {
				if strings.Contains(f, "requests") && i > 0 {
					p.Requests = safeAtoi(fields[i-1])
					break
				}
			}
		}
		if strings.Contains(ll, "number of requests:") {
			num := strings.TrimSpace(strings.TrimPrefix(ll, "[~] number of requests:"))
			p.Requests = safeAtoi(num)
		}
	}
	return p
}

// runNmapTop scans top TCP ports and returns Service entries plus raw XML/log.
func runNmapTop(ctx context.Context, host, outDir string) ([]storage.Service, string, error) {
	bin, err := exec.LookPath("nmap")
	if err != nil {
		return nil, "", fmt.Errorf("nmap not installed")
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return nil, "", err
	}
	args := []string{"-Pn", "-sV", "--top-ports", "100", "--open", "-oX", "-", host}
	tctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(tctx, bin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err = cmd.Run()
	raw := buf.String()
	_ = os.WriteFile(filepath.Join(outDir, "nmap.xml"), []byte(raw), 0o640)
	_ = os.WriteFile(filepath.Join(outDir, "nmap.log"), []byte(raw), 0o640)
	if tctx.Err() == context.DeadlineExceeded {
		return nil, raw, fmt.Errorf("nmap timeout")
	}
	if err != nil {
		return nil, raw, fmt.Errorf("nmap failed: %v", err)
	}

	services := parseNmapXML(raw, host)
	return services, raw, nil
}

// parseNmapXML decodes a minimal subset of the nmap XML output.
func parseNmapXML(raw string, host string) []storage.Service {
	type nmapService struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
	}
	type nmapState struct {
		State string `xml:"state,attr"`
	}
	type nmapPort struct {
		Protocol string      `xml:"protocol,attr"`
		PortID   int         `xml:"portid,attr"`
		State    nmapState   `xml:"state"`
		Service  nmapService `xml:"service"`
	}
	type nmapRun struct {
		Ports []nmapPort `xml:"host>ports>port"`
	}
	var doc nmapRun
	if err := xml.Unmarshal([]byte(raw), &doc); err != nil {
		return nil
	}
	out := make([]storage.Service, 0, len(doc.Ports))
	for _, p := range doc.Ports {
		if strings.ToLower(p.State.State) != "open" {
			continue
		}
		name := p.Service.Name
		if name == "" {
			name = p.Service.Product
		}
		banner := strings.TrimSpace(strings.Join([]string{p.Service.Product, p.Service.Version}, " "))
		out = append(out, storage.Service{
			Port:     p.PortID,
			Protocol: strings.ToLower(p.Protocol),
			Name:     name,
			Banner:   strings.TrimSpace(banner),
		})
	}
	return out
}

// mergeServiceMetadata maps parsed services into existing assets later.
func attachHost(services []storage.Service, host string) []storage.Service { return services }

// stringSliceLimit returns first n non-empty items.
func stringSliceLimit(in []string, n int) string {
	if len(in) == 0 {
		return ""
	}
	if len(in) > n {
		in = in[:n]
	}
	return strings.Join(in, ", ")
}

func summaryWaf(res wafw00fResult) string {
	if res.Detected {
		if res.Name != "" {
			return "WAF detectado: " + res.Name
		}
		return "WAF detectado"
	}
	return "Nenhum WAF detectado"
}

// safeAtoi converts string to int with default 0.
func safeAtoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
