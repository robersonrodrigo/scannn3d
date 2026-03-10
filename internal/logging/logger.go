package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

func New(outputDir string, verbose bool) (*slog.Logger, func(), error) {
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return nil, nil, err
	}

	auditPath := filepath.Join(outputDir, "audit.log")
	f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, nil, err
	}

	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	mw := io.MultiWriter(os.Stdout, f)
	handler := slog.NewJSONHandler(mw, &slog.HandlerOptions{Level: level})
	logger := slog.New(handler)
	cleanup := func() {
		_ = f.Close()
	}
	return logger, cleanup, nil
}
