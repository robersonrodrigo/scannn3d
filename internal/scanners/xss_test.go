package scanners

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scannn3d/internal/config"
	"scannn3d/internal/core"
	"scannn3d/internal/ratelimit"
	"scannn3d/internal/request"
	"scannn3d/internal/scope"
)

func TestXSSScanner_Scan(t *testing.T) {
	tests := []struct {
		name          string
		responseBody  string // Use %s for the injected value
		expectedTitle string
		expectedFound bool
	}{
		{
			name:          "Reflected in Body",
			responseBody:  "<html><body><div>%s</div></body></html>",
			expectedTitle: "Potential Reflected XSS",
			expectedFound: true,
		},
		{
			name:          "Reflected in Attribute",
			responseBody:  "<html><body><input value=\"%s\"></body></html>",
			expectedTitle: "Potential Reflected XSS",
			expectedFound: true,
		},
		{
			name:          "Reflected in Script",
			responseBody:  "<html><script>var x = '%s';</script></html>",
			expectedTitle: "Potential Reflected XSS",
			expectedFound: true,
		},
		{
			name:          "No Reflection",
			responseBody:  "<html><body>Safe Content</body></html>",
			expectedFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				val := r.URL.Query().Get("q")
				if strings.Contains(tt.responseBody, "%s") {
					fmt.Fprintf(w, tt.responseBody, val)
					return
				}
				_, _ = io.WriteString(w, tt.responseBody)
			}))
			defer ts.Close()

			sc := scope.New([]string{"localhost", "127.0.0.1", "::1"})
			lim := ratelimit.New(100, 100)
			rm := request.New(time.Second, true, lim, sc, nil, config.AuthConfig{})
			s := NewXSSScanner()

			tr := core.TargetRequest{
				Method: "GET",
				URL:    ts.URL + "?q=initial",
			}

			findings, err := s.Scan(context.Background(), tr, rm)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if tt.expectedFound {
				if len(findings) == 0 {
					t.Fatalf("Expected findings for %s, got 0", tt.name)
				}
				if findings[0].Title != tt.expectedTitle {
					t.Errorf("Expected title %q, got %q", tt.expectedTitle, findings[0].Title)
				}
				// Verify raw info is captured
				if findings[0].RawRequest == "" || findings[0].RawResponse == "" {
					t.Error("Raw evidence not captured")
				}
			} else {
				if len(findings) > 0 {
					t.Errorf("Expected 0 findings for %s, got %d", tt.name, len(findings))
				}
			}
		})
	}
}
