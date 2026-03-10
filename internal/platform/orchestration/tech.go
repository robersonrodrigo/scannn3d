package orchestration

import "strings"

func classifyTech(tech []string) string {
	if len(tech) == 0 {
		return "web"
	}
	lower := strings.ToLower(strings.Join(tech, ","))
	switch {
	case strings.Contains(lower, "api"):
		return "api"
	case strings.Contains(lower, "wordpress"):
		return "wordpress"
	case strings.Contains(lower, "drupal"):
		return "drupal"
	case strings.Contains(lower, "java") || strings.Contains(lower, "spring"):
		return "java"
	case strings.Contains(lower, "php"):
		return "php"
	case strings.Contains(lower, "asp.net"):
		return "dotnet"
	case strings.Contains(lower, "node") || strings.Contains(lower, "express"):
		return "nodejs"
	default:
		return "web"
	}
}
