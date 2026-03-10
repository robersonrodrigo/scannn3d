package webscan

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"scannn3d/internal/platform/storage"
)

var linkRe = regexp.MustCompile(`(?i)href=["']([^"'#]+)["']`)

var sstiPayloads = []struct {
	payload string
	expect  string
}{
	{"{{7*7}}", "49"},
	{"${7*7}", "49"},
	{"<%= 7*7 %>", "49"},
}

var traversalPayloads = []string{
	"../../../../../../etc/passwd",
	"..%2f..%2f..%2f..%2fetc%2fpasswd",
}

func ScanWeb(ctx context.Context, target string) ([]storage.Application, []storage.Vulnerability) {
	app := storage.Application{BaseURL: target, AppType: classifyType(target)}

	client := &http.Client{Timeout: 8 * time.Second}
	baseResp, baseBody, err := fetch(ctx, client, target, nil)
	if err != nil {
		return []storage.Application{app}, []storage.Vulnerability{{
			Type:           "availability",
			Severity:       "medium",
			Title:          "Target Unreachable",
			Description:    "Web target could not be reached.",
			Evidence:       err.Error(),
			Recommendation: "Validate target availability and TLS/network path.",
			CreatedAt:      time.Now().UTC(),
		}}
	}

	vulns := make([]storage.Vulnerability, 0, 14)
	vulns = append(vulns, checkHeaders(baseResp.Header)...)
	vulns = append(vulns, checkReflectedXSS(ctx, client, target)...)
	vulns = append(vulns, checkSQLi(ctx, client, target, baseResp.StatusCode, baseBody)...)
	vulns = append(vulns, checkSSRF(ctx, client, target, baseResp.StatusCode)...)
	vulns = append(vulns, checkBOLA(ctx, client, target, baseResp.StatusCode, baseBody)...)
	vulns = append(vulns, checkJWT(ctx, client, target, baseResp.StatusCode, baseResp.Header)...)
	vulns = append(vulns, endpointDisclosure(target, baseBody)...)
	vulns = append(vulns, checkCommandInjection(ctx, client, target, baseBody)...)
	vulns = append(vulns, checkSSTI(ctx, client, target)...)
	vulns = append(vulns, checkOpenRedirect(ctx, client, target)...)
	vulns = append(vulns, checkPathTraversal(ctx, client, target, baseBody)...)
	vulns = append(vulns, checkHTTPMethods(ctx, target)...)
	vulns = append(vulns, checkTLS(target)...)

	return []storage.Application{app}, vulns
}

func classifyType(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return "web"
	}
	if strings.Contains(strings.ToLower(u.Path), "/api") {
		return "api"
	}
	return "web"
}

func checkHeaders(h http.Header) []storage.Vulnerability {
	needed := []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Strict-Transport-Security"}
	out := make([]storage.Vulnerability, 0, len(needed))
	for _, k := range needed {
		if strings.TrimSpace(h.Get(k)) == "" {
			out = append(out, storage.Vulnerability{
				Type:           "insecure-header",
				Severity:       "medium",
				Title:          "Missing Security Header",
				Description:    "Security header not present in HTTP response.",
				Evidence:       k,
				Recommendation: "Configure defensive HTTP headers on edge and app layers.",
				CreatedAt:      time.Now().UTC(),
			})
		}
	}
	if strings.TrimSpace(h.Get("Access-Control-Allow-Origin")) == "*" && strings.EqualFold(strings.TrimSpace(h.Get("Access-Control-Allow-Credentials")), "true") {
		out = append(out, storage.Vulnerability{
			Type:           "cors-misconfig",
			Severity:       "high",
			Title:          "Insecure CORS Policy",
			Description:    "Wildcard CORS origin combined with credentials can expose sensitive responses.",
			Evidence:       "acao=* acac=true",
			Recommendation: "Restrict allowed origins and avoid credentials with wildcard origin.",
			CreatedAt:      time.Now().UTC(),
		})
	}
	return out
}

func checkHTTPMethods(ctx context.Context, target string) []storage.Vulnerability {
	req, _ := http.NewRequestWithContext(ctx, http.MethodOptions, target, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	_ = resp.Body.Close()
	allow := strings.ToUpper(resp.Header.Get("Allow"))
	if allow == "" {
		return nil
	}
	find := func(method string) bool { return strings.Contains(allow, method) }
	vulns := []storage.Vulnerability{}
	if find("PUT") || find("DELETE") || find("TRACE") {
		vulns = append(vulns, storage.Vulnerability{
			Type:           "insecure-methods",
			Severity:       "medium",
			Title:          "Metodos HTTP potencialmente inseguros habilitados",
			Description:    "Allow header exposto indica metodos sensiveis habilitados.",
			Evidence:       allow,
			Recommendation: "Restringir metodos a GET/POST necessários ou exigir autenticação forte.",
			CreatedAt:      time.Now().UTC(),
		})
	}
	return vulns
}

func checkTLS(target string) []storage.Vulnerability {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" {
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 4 * time.Second}, "tcp", net.JoinHostPort(host, port), &tls.Config{ServerName: host})
	if err != nil {
		return []storage.Vulnerability{{
			Type:           "tls-unreachable",
			Severity:       "medium",
			Title:          "TLS handshake falhou",
			Description:    "Nao foi possivel completar handshake TLS.",
			Evidence:       err.Error(),
			Recommendation: "Verificar certificado, chain e protocolos aceitos.",
			CreatedAt:      time.Now().UTC(),
		}}
	}
	defer conn.Close()
	state := conn.ConnectionState()
	ver := tlsVersionName(state.Version)
	if state.Version < tls.VersionTLS12 {
		return []storage.Vulnerability{{
			Type:           "tls-version",
			Severity:       "medium",
			Title:          "Versao TLS fraca",
			Description:    "Versao TLS negociada inferior a 1.2.",
			Evidence:       ver,
			Recommendation: "Forcar TLS1.2 ou superior; desabilitar suites fracas.",
			CreatedAt:      time.Now().UTC(),
		}}
	}
	return nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func checkCommandInjection(ctx context.Context, client *http.Client, target string, baseBody string) []storage.Vulnerability {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	q := u.Query()
	param := firstParam(q)
	q.Set(param, "test;id")
	u.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	_, body, err := doRequest(ctx, client, req)
	if err != nil {
		return nil
	}
	if strings.Contains(body, "uid=") || strings.Contains(body, "gid=") {
		return []storage.Vulnerability{{
			Type:           "cmd-injection",
			Severity:       "high",
			Title:          "Possivel Command Injection",
			Description:    "Resposta parece conter resultado de comando shell.",
			Evidence:       "uid= pattern detected",
			Recommendation: "Sanitizar entrada, usar exec seguro, validar lista branca.",
			CreatedAt:      time.Now().UTC(),
		}}
	}
	_ = baseBody
	return nil
}

func checkSSTI(ctx context.Context, client *http.Client, target string) []storage.Vulnerability {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	q := u.Query()
	param := firstParam(q)
	for _, p := range sstiPayloads {
		q.Set(param, p.payload)
		u.RawQuery = q.Encode()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		_, body, err := doRequest(ctx, client, req)
		if err != nil {
			continue
		}
		if strings.Contains(body, p.expect) {
			return []storage.Vulnerability{{
				Type:           "ssti",
				Severity:       "high",
				Title:          "Server-Side Template Injection",
				Description:    "Payload de template foi avaliado no servidor.",
				Evidence:       fmt.Sprintf("payload=%s expect=%s", p.payload, p.expect),
				Recommendation: "Escapar contexto de template, usar sandbox e validacao de dados.",
				CreatedAt:      time.Now().UTC(),
			}}
		}
	}
	return nil
}

func checkOpenRedirect(ctx context.Context, client *http.Client, target string) []storage.Vulnerability {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	q := u.Query()
	param := findRedirectParam(q)
	if param == "" {
		return nil
	}
	mal := "https://evil.example.com"
	q.Set(param, mal)
	u.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.HasPrefix(loc, mal) {
		return []storage.Vulnerability{{
			Type:           "open-redirect",
			Severity:       "medium",
			Title:          "Open Redirect",
			Description:    "Parametro de redirecionamento permite destinos arbitrarios.",
			Evidence:       fmt.Sprintf("location=%s param=%s", loc, param),
			Recommendation: "Validar destino, usar lista branca ou tokens de estado.",
			CreatedAt:      time.Now().UTC(),
		}}
	}
	return nil
}

func checkPathTraversal(ctx context.Context, client *http.Client, target string, baseBody string) []storage.Vulnerability {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	q := u.Query()
	param := firstParam(q)
	for _, p := range traversalPayloads {
		q.Set(param, p)
		u.RawQuery = q.Encode()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		_, body, err := doRequest(ctx, client, req)
		if err != nil {
			continue
		}
		if strings.Contains(body, "root:x:") || strings.Contains(body, "[boot loader]") {
			return []storage.Vulnerability{{
				Type:           "path-traversal",
				Severity:       "high",
				Title:          "Directory Traversal / LFI",
				Description:    "Payload de traversal retornou conteudo sensivel.",
				Evidence:       "Found passwd signature",
				Recommendation: "Normalizar paths, bloquear ../ e validar recursos.",
				CreatedAt:      time.Now().UTC(),
			}}
		}
	}
	return nil
}

func firstParam(q url.Values) string {
	for k := range q {
		return k
	}
	return "q"
}

func findRedirectParam(q url.Values) string {
	for k := range q {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "redirect") || strings.Contains(lk, "next") || strings.Contains(lk, "return") || strings.Contains(lk, "url") {
			return k
		}
	}
	return ""
}

func checkReflectedXSS(ctx context.Context, client *http.Client, target string) []storage.Vulnerability {
	payload := "<script>alert(1337)</script>"
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	q := u.Query()
	q.Set("q", payload)
	u.RawQuery = q.Encode()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	_, body, err := doRequest(ctx, client, req)
	if err != nil {
		return nil
	}
	if strings.Contains(body, payload) {
		return []storage.Vulnerability{{
			Type:           "xss-reflected",
			Severity:       "high",
			Title:          "Potential Reflected XSS",
			Description:    "Injected script payload reflected in response.",
			Evidence:       fmt.Sprintf("url=%s", u.String()),
			Recommendation: "Apply context-aware output encoding and CSP.",
			CreatedAt:      time.Now().UTC(),
		}}
	}
	return nil
}

func checkSQLi(ctx context.Context, client *http.Client, target string, baseStatus int, baseBody string) []storage.Vulnerability {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	q := u.Query()
	param := "id"
	if len(q) == 0 {
		q.Set("id", "1")
	} else {
		for k := range q {
			param = k
			break
		}
	}

	trueURL := *u
	trueQ := trueURL.Query()
	trueQ.Set(param, "1' AND '1'='1")
	trueURL.RawQuery = trueQ.Encode()
	falseURL := *u
	falseQ := falseURL.Query()
	falseQ.Set(param, "1' AND '1'='2")
	falseURL.RawQuery = falseQ.Encode()

	respT, bodyT, errT := fetch(ctx, client, trueURL.String(), nil)
	respF, bodyF, errF := fetch(ctx, client, falseURL.String(), nil)
	if errT != nil || errF != nil {
		return nil
	}
	lowerTrue := strings.ToLower(bodyT)
	if strings.Contains(lowerTrue, "sql") || strings.Contains(lowerTrue, "syntax") || (respT.StatusCode >= 500 && baseStatus < 500) {
		return []storage.Vulnerability{{
			Type:           "sqli-basic",
			Severity:       "high",
			Title:          "Potential SQL Injection",
			Description:    "Mutated parameter triggered SQL-like fault behavior.",
			Evidence:       fmt.Sprintf("url=%s status=%d", trueURL.String(), respT.StatusCode),
			Recommendation: "Use parameterized queries and suppress DB error leakage.",
			CreatedAt:      time.Now().UTC(),
		}}
	}
	baseSim := similarity(baseBody, bodyT)
	falseSim := similarity(baseBody, bodyF)
	if respT.StatusCode < 400 && (respF.StatusCode >= 400 || (baseSim >= 0.9 && falseSim <= 0.75)) {
		return []storage.Vulnerability{{
			Type:           "sqli-boolean",
			Severity:       "high",
			Title:          "Potential SQL Injection (Boolean-Based)",
			Description:    "True/false SQL condition produced divergent application behavior.",
			Evidence:       fmt.Sprintf("param=%s true_status=%d false_status=%d base_sim=%.2f false_sim=%.2f", param, respT.StatusCode, respF.StatusCode, baseSim, falseSim),
			Recommendation: "Enforce prepared statements and strict query parameter validation.",
			CreatedAt:      time.Now().UTC(),
		}}
	}
	return nil
}

func checkSSRF(ctx context.Context, client *http.Client, target string, baseStatus int) []storage.Vulnerability {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	q := u.Query()
	param := "url"
	if len(q) > 0 {
		for k := range q {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "url") || strings.Contains(lk, "redirect") || strings.Contains(lk, "next") || strings.Contains(lk, "dest") || strings.Contains(lk, "callback") {
				param = k
				break
			}
		}
	}
	q.Set(param, "http://169.254.169.254/latest/meta-data/")
	u.RawQuery = q.Encode()
	resp, body, err := fetch(ctx, client, u.String(), nil)
	if err != nil {
		return nil
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "169.254.169.254") || strings.Contains(lower, "metadata") || strings.Contains(lower, "connection refused") || (resp.StatusCode >= 500 && baseStatus < 500) {
		return []storage.Vulnerability{{
			Type:           "ssrf-basic",
			Severity:       "high",
			Title:          "Potential SSRF",
			Description:    "URL parameter mutation suggests backend fetch behavior against internal targets.",
			Evidence:       fmt.Sprintf("param=%s status=%d url=%s", param, resp.StatusCode, u.String()),
			Recommendation: "Validate and allowlist outbound destinations; block internal and link-local ranges.",
			CreatedAt:      time.Now().UTC(),
		}}
	}
	return nil
}

func checkBOLA(ctx context.Context, client *http.Client, target string, baseStatus int, baseBody string) []storage.Vulnerability {
	u, err := url.Parse(target)
	if err != nil {
		return nil
	}
	if baseStatus >= 400 {
		return nil
	}
	q := u.Query()
	param := ""
	baseID := ""
	for k, v := range q {
		if len(v) == 0 {
			continue
		}
		if _, convErr := strconv.Atoi(v[0]); convErr == nil && strings.Contains(strings.ToLower(k), "id") {
			param = k
			baseID = v[0]
			break
		}
	}
	if param == "" {
		return nil
	}
	idNum, _ := strconv.Atoi(baseID)
	q.Set(param, strconv.Itoa(idNum+1))
	u.RawQuery = q.Encode()
	resp, body, err := fetch(ctx, client, u.String(), nil)
	if err != nil {
		return nil
	}
	if resp.StatusCode < 400 && similarity(baseBody, body) < 0.98 && !strings.Contains(strings.ToLower(body), "forbidden") && !strings.Contains(strings.ToLower(body), "unauthorized") {
		return []storage.Vulnerability{{
			Type:           "bola-basic",
			Severity:       "high",
			Title:          "Potential BOLA/IDOR",
			Description:    "Identifier mutation returned a different accessible object without authorization failure.",
			Evidence:       fmt.Sprintf("param=%s base_id=%s mutated_id=%d status=%d", param, baseID, idNum+1, resp.StatusCode),
			Recommendation: "Implement object-level authorization checks on every resource access.",
			CreatedAt:      time.Now().UTC(),
		}}
	}
	return nil
}

func checkJWT(ctx context.Context, client *http.Client, target string, baseStatus int, baseHeaders http.Header) []storage.Vulnerability {
	// Only probe JWT auth bypass when endpoint appears protected.
	if baseStatus < 401 && strings.TrimSpace(baseHeaders.Get("WWW-Authenticate")) == "" {
		return nil
	}
	header, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{"sub": "1", "role": "admin", "exp": time.Now().Add(10 * time.Minute).Unix()})
	token := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
	headers := map[string]string{"Authorization": "Bearer " + token}
	resp, _, err := fetch(ctx, client, target, headers)
	if err != nil {
		return nil
	}
	if resp.StatusCode < 400 {
		return []storage.Vulnerability{{
			Type:           "jwt-none-alg",
			Severity:       "high",
			Title:          "Potential JWT alg=none Acceptance",
			Description:    "Protected endpoint accepted unsigned JWT token.",
			Evidence:       fmt.Sprintf("status=%d", resp.StatusCode),
			Recommendation: "Enforce strict JWT signature and algorithm verification.",
			CreatedAt:      time.Now().UTC(),
		}}
	}
	return nil
}

func endpointDisclosure(base string, body string) []storage.Vulnerability {
	matches := linkRe.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	count := 0
	for _, m := range matches {
		if len(m) > 1 && strings.HasPrefix(strings.TrimSpace(m[1]), "/") {
			count++
		}
	}
	if count >= 25 {
		return []storage.Vulnerability{{
			Type:           "endpoint-surface",
			Severity:       "low",
			Title:          "Large Endpoint Surface",
			Description:    "High number of linked endpoints discovered during basic crawl.",
			Evidence:       fmt.Sprintf("target=%s linked_paths=%d", base, count),
			Recommendation: "Review exposed routes and protect non-public paths.",
			CreatedAt:      time.Now().UTC(),
		}}
	}
	return nil
}

func fetch(ctx context.Context, client *http.Client, target string, headers map[string]string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return doRequest(ctx, client, req)
}

func doRequest(_ context.Context, client *http.Client, req *http.Request) (*http.Response, string, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	bodyBytes := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			bodyBytes = append(bodyBytes, buf[:n]...)
		}
		if readErr != nil {
			break
		}
		if len(bodyBytes) > 500_000 {
			break
		}
	}
	return resp, string(bodyBytes), nil
}

func similarity(a, b string) float64 {
	na := strings.ToLower(strings.Join(strings.Fields(a), " "))
	nb := strings.ToLower(strings.Join(strings.Fields(b), " "))
	if na == "" && nb == "" {
		return 1
	}
	if na == "" || nb == "" {
		return 0
	}
	maxLen := len(na)
	if len(nb) > maxLen {
		maxLen = len(nb)
	}
	minLen := len(na)
	if len(nb) < minLen {
		minLen = len(nb)
	}
	if maxLen == 0 {
		return 1
	}
	match := 0
	for i := 0; i < minLen; i++ {
		if na[i] == nb[i] {
			match++
		}
	}
	return float64(match) / float64(maxLen)
}
