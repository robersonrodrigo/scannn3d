package infra

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

func EnumerateSubdomains(ctx context.Context, domain string) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	bin, err := exec.LookPath("subfinder")
	if err != nil {
		return nil, fmt.Errorf("subfinder is not installed")
	}

	tctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// Keep default CLI behavior aligned with standalone usage: `subfinder -d <domain>`.
	cmd := exec.CommandContext(tctx, bin, "-d", domain)
	out, err := cmd.CombinedOutput()
	if tctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("subfinder timed out")
	}
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("subfinder failed: %s", msg)
	}

	seen := map[string]struct{}{}
	for _, line := range strings.Split(string(out), "\n") {
		sub := strings.ToLower(strings.TrimSpace(line))
		if sub == "" {
			continue
		}
		if strings.HasPrefix(sub, "[inf]") || strings.HasPrefix(sub, "[wrn]") || strings.HasPrefix(sub, "[err]") {
			continue
		}
		if strings.Contains(sub, "projectdiscovery.io") {
			continue
		}
		if strings.HasPrefix(sub, "__") || strings.HasPrefix(sub, "/") || strings.HasPrefix(sub, "(") {
			continue
		}
		if !strings.HasSuffix(sub, "."+domain) && sub != domain {
			continue
		}
		seen[sub] = struct{}{}
	}
	list := make([]string, 0, len(seen))
	for sub := range seen {
		list = append(list, sub)
	}
	sort.Strings(list)
	return list, nil
}
