package core

import (
	"context"
	"net/http"
	"time"

	"scannn3d/internal/request"
)

type Finding struct {
	Module         string    `json:"module"`
	Severity       string    `json:"severity"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Endpoint       string    `json:"endpoint"`
	Method         string    `json:"method"`
	Evidence       string    `json:"evidence"`
	Recommendation string    `json:"recommendation"`
	RawRequest     string    `json:"raw_request,omitempty"`
	RawResponse    string    `json:"raw_response,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}

type TargetRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    string
}

type Scanner interface {
	Name() string
	Scan(ctx context.Context, tr TargetRequest, rm *request.Manager) ([]Finding, error)
}
