package core

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"scannn3d/internal/request"
)

type Engine struct {
	scanners    []Scanner
	rm          *request.Manager
	concurrency int
	logger      *slog.Logger
}

func New(scanners []Scanner, rm *request.Manager, concurrency int, logger *slog.Logger) *Engine {
	if concurrency <= 0 {
		concurrency = 4
	}
	return &Engine{scanners: scanners, rm: rm, concurrency: concurrency, logger: logger}
}

func (e *Engine) Run(ctx context.Context, targets []TargetRequest) ([]Finding, error) {
	if len(e.scanners) == 0 {
		return nil, fmt.Errorf("no scanners loaded")
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}

	sem := make(chan struct{}, e.concurrency)
	findingsCh := make(chan []Finding, len(targets)*len(e.scanners))
	errCh := make(chan error, len(targets)*len(e.scanners))

	var wg sync.WaitGroup
	for _, tr := range targets {
		for _, scanner := range e.scanners {
			tr := tr
			scanner := scanner
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				e.logger.Info("scan_started", "module", scanner.Name(), "target", tr.URL)
				start := time.Now()
				f, err := scanner.Scan(ctx, tr, e.rm)
				if err != nil {
					errCh <- fmt.Errorf("%s on %s failed: %w", scanner.Name(), tr.URL, err)
					return
				}
				e.logger.Info("scan_finished", "module", scanner.Name(), "target", tr.URL, "finding_count", len(f), "elapsed_ms", time.Since(start).Milliseconds())
				if len(f) > 0 {
					findingsCh <- f
				}
			}()
		}
	}

	wg.Wait()
	close(findingsCh)
	close(errCh)

	all := make([]Finding, 0, 32)
	for f := range findingsCh {
		all = append(all, f...)
	}

	for err := range errCh {
		e.logger.Warn("scanner_error", "err", err)
	}

	return all, nil
}
