package ratelimit

import (
	"context"
	"time"
)

type Limiter struct {
	tokens chan struct{}
}

func New(rps int, burst int) *Limiter {
	if rps <= 0 {
		rps = 5
	}
	if burst <= 0 {
		burst = rps
	}
	l := &Limiter{tokens: make(chan struct{}, burst)}

	for i := 0; i < burst; i++ {
		l.tokens <- struct{}{}
	}

	interval := time.Second / time.Duration(rps)
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			select {
			case l.tokens <- struct{}{}:
			default:
			}
		}
	}()
	return l
}

func (l *Limiter) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.tokens:
		return nil
	}
}
