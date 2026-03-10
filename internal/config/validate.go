package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

func ValidateAndDefault(cfg *Config) error {
	u, err := url.Parse(cfg.Target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("target must be a valid absolute URL")
	}

	cfg.Method = strings.ToUpper(strings.TrimSpace(cfg.Method))
	if cfg.Method == "" {
		cfg.Method = "GET"
	}

	if len(cfg.Endpoints) == 0 {
		cfg.Endpoints = []string{"/"}
	}
	if len(cfg.ScopeHosts) == 0 {
		cfg.ScopeHosts = []string{u.Hostname()}
	}
	if cfg.Rate <= 0 {
		cfg.Rate = 10
	}
	if cfg.Burst <= 0 {
		cfg.Burst = cfg.Rate
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}
	if cfg.CrawlDepth < 0 {
		return fmt.Errorf("crawl-depth must be >= 0")
	}
	if cfg.ExternalTimeout <= 0 {
		cfg.ExternalTimeout = 8 * time.Minute
	}
	if strings.TrimSpace(cfg.DirsearchProfile) == "" {
		cfg.DirsearchProfile = "auto"
	}
	cfg.DirsearchProfile = strings.ToLower(strings.TrimSpace(cfg.DirsearchProfile))
	switch cfg.DirsearchProfile {
	case "auto", "generic-web", "api-rest", "spa", "wordpress", "drupal", "joomla", "laravel", "django", "rails", "node-express":
	default:
		return fmt.Errorf("unsupported dirsearch profile: %s", cfg.DirsearchProfile)
	}
	if strings.TrimSpace(cfg.DirsearchIntensity) == "" {
		cfg.DirsearchIntensity = "balanced"
	}
	cfg.DirsearchIntensity = strings.ToLower(strings.TrimSpace(cfg.DirsearchIntensity))
	switch cfg.DirsearchIntensity {
	case "conservative", "balanced", "aggressive":
	default:
		return fmt.Errorf("unsupported dirsearch intensity: %s", cfg.DirsearchIntensity)
	}

	if cfg.OpenAPIFile != "" {
		if _, err := os.Stat(cfg.OpenAPIFile); err != nil {
			return fmt.Errorf("openapi file not accessible: %w", err)
		}
	}
	if cfg.PostmanFile != "" {
		if _, err := os.Stat(cfg.PostmanFile); err != nil {
			return fmt.Errorf("postman file not accessible: %w", err)
		}
	}

	switch cfg.Auth.Type {
	case AuthNone, AuthBearer, AuthBasic, AuthAPIKey:
		return nil
	default:
		return fmt.Errorf("unsupported auth type: %s", cfg.Auth.Type)
	}
}
