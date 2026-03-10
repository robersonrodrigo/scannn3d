package scope

import (
	"fmt"
	"net/url"
	"strings"
)

type Controller struct {
	allowed map[string]struct{}
}

func New(hosts []string) *Controller {
	allowed := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" {
			continue
		}
		allowed[h] = struct{}{}
	}
	return &Controller{allowed: allowed}
}

func (c *Controller) Validate(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	host := strings.ToLower(u.Hostname())
	if len(c.allowed) == 0 {
		return nil
	}
	if _, ok := c.allowed[host]; ok {
		return nil
	}
	return fmt.Errorf("url host %q is outside allowed scope", host)
}
