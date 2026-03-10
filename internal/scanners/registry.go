package scanners

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"scannn3d/internal/core"
)

func All(templateDir string, logger *slog.Logger) []core.Scanner {
	base := []core.Scanner{
		NewPassiveScanner(),
		NewSQLiScanner(),
		NewXSSScanner(),
		NewSSRFScanner(),
		NewJWTScanner(),
		NewBOLAScanner(),
	}

	if templateDir != "" {
		if _, err := os.Stat(templateDir); err == nil {
			templates, err := LoadTemplates(templateDir, logger)
			if err != nil {
				logger.Warn("templates_load_failed", "dir", templateDir, "err", err)
			} else {
				base = append(base, templates...)
			}
		}
	}

	return base
}

func Select(names []string, templateDir string, logger *slog.Logger) ([]core.Scanner, error) {
	all := All(templateDir, logger)
	if len(names) == 0 {
		return all, nil
	}
	catalog := map[string]core.Scanner{}
	for _, s := range all {
		catalog[strings.ToLower(s.Name())] = s
	}

	selected := make([]core.Scanner, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(strings.ToLower(n))
		if n == "all" {
			return all, nil
		}
		s, ok := catalog[n]
		if !ok {
			return nil, fmt.Errorf("unknown module: %s", n)
		}
		selected = append(selected, s)
	}
	return selected, nil
}
