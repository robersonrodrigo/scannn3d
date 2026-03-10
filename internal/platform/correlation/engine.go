package correlation

import (
	"fmt"
	"strings"

	"scannn3d/internal/platform/storage"
)

func BuildGraph(scan storage.Scan, target storage.Target, assets []storage.Asset, services []storage.Service, apps []storage.Application, vulns []storage.Vulnerability) ([]storage.GraphNode, []storage.GraphEdge) {
	nodes := make([]storage.GraphNode, 0, 8+len(services)+len(vulns))
	edges := make([]storage.GraphEdge, 0, 16)

	hostNode := storage.GraphNode{Kind: "host", RefID: target.ID, Label: target.Address}
	nodes = append(nodes, hostNode)

	serviceNodeIDs := make([]int, 0, len(services))
	for _, s := range services {
		n := storage.GraphNode{Kind: "service", RefID: s.ID, Label: fmt.Sprintf("%s/%d", s.Name, s.Port), Metadata: map[string]any{"port": s.Port, "protocol": s.Protocol}}
		nodes = append(nodes, n)
		serviceNodeIDs = append(serviceNodeIDs, len(nodes)-1)
		edges = append(edges, storage.GraphEdge{Type: "HOSTS_SERVICE", FromID: hostNode.RefID, ToID: n.RefID})
	}

	appNodeIDs := make([]int, 0, len(apps))
	for _, a := range apps {
		n := storage.GraphNode{Kind: "application", RefID: a.ID, Label: a.BaseURL, Metadata: map[string]any{"type": a.AppType}}
		nodes = append(nodes, n)
		appNodeIDs = append(appNodeIDs, len(nodes)-1)
		if len(serviceNodeIDs) > 0 {
			edges = append(edges, storage.GraphEdge{Type: "SERVICE_EXPOSES_APP", FromID: nodes[serviceNodeIDs[0]].RefID, ToID: n.RefID})
		} else {
			edges = append(edges, storage.GraphEdge{Type: "HOST_EXPOSES_APP", FromID: hostNode.RefID, ToID: n.RefID})
		}
	}

	for _, v := range vulns {
		n := storage.GraphNode{Kind: "vulnerability", RefID: v.ID, Label: v.Title, Metadata: map[string]any{"severity": v.Severity, "type": v.Type}}
		nodes = append(nodes, n)
		from := hostNode.RefID
		if len(appNodeIDs) > 0 {
			from = nodes[appNodeIDs[0]].RefID
		}
		edges = append(edges, storage.GraphEdge{Type: "APP_HAS_VULN", FromID: from, ToID: n.RefID})
	}

	return nodes, edges
}

func BuildAttackChain(target storage.Target, services []storage.Service, apps []storage.Application, vulns []storage.Vulnerability) storage.AttackChain {
	steps := make([]storage.AttackChainStep, 0, 5)
	hasHTTP := false
	for _, s := range services {
		if s.Name == "http" || s.Name == "https" {
			hasHTTP = true
			break
		}
	}
	hasSQLi, hasXSS, hasWeakHeaders := false, false, false
	for _, v := range vulns {
		l := strings.ToLower(v.Type + " " + v.Title)
		switch {
		case strings.Contains(l, "sqli") || strings.Contains(l, "sql"):
			hasSQLi = true
		case strings.Contains(l, "xss"):
			hasXSS = true
		case strings.Contains(l, "header"):
			hasWeakHeaders = true
		}
	}

	idx := 1
	if hasHTTP && len(apps) > 0 {
		steps = append(steps, storage.AttackChainStep{Step: idx, Title: "Initial Access via Web Surface", Description: "HTTP service and application surface discovered.", Confidence: "high"})
		idx++
	}
	if hasXSS {
		steps = append(steps, storage.AttackChainStep{Step: idx, Title: "Session/Browser Abuse Candidate", Description: "Reflected XSS may allow token theft or privileged actions.", Confidence: "medium"})
		idx++
	}
	if hasSQLi {
		steps = append(steps, storage.AttackChainStep{Step: idx, Title: "Data Access Escalation Candidate", Description: "SQL injection may expose backend data and pivot opportunities.", Confidence: "high"})
		idx++
	}
	if hasWeakHeaders && (hasSQLi || hasXSS) {
		steps = append(steps, storage.AttackChainStep{Step: idx, Title: "Compound Exploitability", Description: "Multiple weaknesses increase practical attack reliability.", Confidence: "medium"})
	}
	if len(steps) == 0 {
		steps = append(steps, storage.AttackChainStep{Step: 1, Title: "No Correlated Chain", Description: "No meaningful exploit chain could be inferred from current findings.", Confidence: "low"})
	}
	return storage.AttackChain{Target: target.Address, Steps: steps, Summary: fmt.Sprintf("%d correlated steps", len(steps))}
}
