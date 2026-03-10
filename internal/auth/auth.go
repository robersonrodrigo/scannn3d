package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"scannn3d/internal/config"
)

func Apply(req *http.Request, cfg config.AuthConfig) error {
	switch cfg.Type {
	case "", config.AuthNone:
		return nil
	case config.AuthBearer:
		if req.Header.Get("Authorization") != "" {
			return nil
		}
		if cfg.Token == "" {
			return fmt.Errorf("bearer token is empty")
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		return nil
	case config.AuthBasic:
		if req.Header.Get("Authorization") != "" {
			return nil
		}
		if cfg.Username == "" {
			return fmt.Errorf("basic auth username is empty")
		}
		raw := cfg.Username + ":" + cfg.Password
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(raw)))
		return nil
	case config.AuthAPIKey:
		if cfg.APIKey == "" {
			return fmt.Errorf("api key is empty")
		}
		h := cfg.APIHeader
		if strings.TrimSpace(h) == "" {
			h = "X-API-Key"
		}
		if req.Header.Get(h) != "" {
			return nil
		}
		req.Header.Set(h, cfg.APIKey)
		return nil
	default:
		return fmt.Errorf("unsupported auth type: %s", cfg.Type)
	}
}
