# Offensive Security Platform MVP

## Components (estado atual)
- `cmd/platform-api`: REST API + Web UI embutida (porta padrão :8095).
- `cmd/platform-cli`: CLI técnica para disparo/listagem de scans.
- `internal/platform/orchestration`: orquestra pipeline, eventos SSE e step_results.
- `internal/platform/infra`: TCP + fingerprint via nmap top-ports.
- `internal/platform/webscan`: crawl-lite + módulos: headers, XSS, SQLi, SSRF, BOLA, JWT, command injection, SSTI, open redirect, path traversal/LFI, métodos HTTP inseguros, TLS versão.
- `internal/platform/recon`: subfinder + validação de subdomínios.
- `internal/platform/pentest`: orquestração segura de Dirsearch/FFUF/Nuclei/Nmap com controle de concorrência, stop/cancel e auditoria.
- `internal/platform/correlation`: grafo e cadeia de ataque.
- `internal/platform/report`: JSON/HTML (inclui etapas e CVSS básico por vuln).
- `internal/platform/storage`: store in-memory + SQLite + PostgreSQL.

## Main API routes
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/scans`
- `GET /api/v1/scans`
- `GET /api/v1/scans/{id}`
- `GET /api/v1/targets`
- `GET /api/v1/targets/{id}`
- `GET /api/v1/vulnerabilities`
- `GET /api/v1/graphs/targets/{targetId}`
- `GET /api/v1/chains/targets/{targetId}`
- `GET /api/v1/reports/scans/{scanId}.json`
- `GET /api/v1/reports/scans/{scanId}.html`
- `POST /api/v1/pentest/jobs`
- `GET /api/v1/pentest/jobs`
- `GET /api/v1/pentest/jobs/{id}`
- `POST /api/v1/pentest/jobs/{id}/stop`
- `GET /api/v1/pentest/jobs/{id}/events/history?since=0`
- `GET /api/v1/pentest/jobs/{id}/events?since=0`
- `GET /api/v1/pentest/jobs/{id}/report.txt`
- `GET /api/v1/pentest/ws/{id}?since=0` (autenticacao via subprotocol WebSocket: `scannn3d.jwt.<jwt>`)

## Run API
```bash
go run ./cmd/platform-api
```
Admin user: `admin`.
Set `PLATFORM_ADMIN_PASSWORD` before first run to control the initial password.
If not set, the API generates a random password and logs it at startup.
`PLATFORM_JWT_SECRET` e obrigatorio (minimo 32 caracteres).

## Run with Docker Compose (single entrypoint)
```bash
cp .env.example .env
# ajuste os placeholders no arquivo .env
docker compose up -d --build platform-api
```

Persistência padrão no compose:
- `PLATFORM_DB_DRIVER=postgres`
- `PLATFORM_DB_DSN=host=pgbouncer port=5432 user=... password=... dbname=... sslmode=disable`
Open:
```text
http://localhost:8095
```
Logs (container):
```bash
docker compose logs -f platform-api
```
Saída de relatórios/eventos:
- `platform-runs/<scan-id>/events.log`
- `platform-runs/<scan-id>/platform-report.{json,html}`
- `platform-runs/pentest/YYYY-MM-DD/<target>/<job-id>/summary.txt`
- `platform-runs/pentest/YYYY-MM-DD/<target>/<job-id>/{dirsearch,ffuf,nuclei,nmap}.txt`
- `platform-runs/pentest/audit.log`

## Pentest Jobs (novo módulo WEB/INFRA)
- `module=web`: `dirsearch`, `ffuf`, `nuclei`
- `module=infra`: `nmap`
- `target_type`: `url|ip|auto`
- argumentos customizados por ferramenta são validados por allowlist no backend.
- execução sem shell (`exec.CommandContext`), com timeout por ferramenta e logs em tempo real.
- stop/cancel: `POST /api/v1/pentest/jobs/{id}/stop`

Exemplo criação WEB:
```bash
curl -X POST http://localhost:8095/api/v1/pentest/jobs \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "target":"https://example.com",
    "target_type":"url",
    "module":"web",
    "threads":20,
    "tools":["dirsearch","ffuf","nuclei"],
    "tool_args":{
      "ffuf":{"rate":"80"},
      "nuclei":{"severity":"high,critical"}
    }
  }'
```

Exemplo criação INFRA:
```bash
curl -X POST http://localhost:8095/api/v1/pentest/jobs \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "target":"192.168.1.10",
    "target_type":"ip",
    "module":"infra",
    "tools":["nmap"],
    "tool_args":{"nmap":{"top_ports":"200","scripts":"vuln"}}
  }'
```

## Run CLI
```bash
go run ./cmd/platform-cli --target https://example.com --full
```
List scans:
```bash
go run ./cmd/platform-cli --list
```

## Deprecation notice
- `cmd/scannn3d-ui` and `cmd/scannn3d` are legacy compatibility binaries.
- Unified platform entrypoints are `platform-api` (web/api) and `platform-cli` (technical CLI).

## Pipeline de URL (atual)
1. wafw00f → fingerprint de WAF.
2. whatweb → fingerprint de tecnologias.
3. nmap top-100 → portas/serviços.
4. Web/API modules → XSS, SQLi, SSRF, JWT, BOLA, command injection, SSTI, open redirect, path traversal/LFI, headers, CORS, métodos inseguros, TLS versão.
5. Correlação + relatórios + attack chain.

## Visualização
- Terminal live por SSE.
- Tabela “Etapas do Scan” na UI listando status/resumo de cada step.
- Subdomínios descobertos (quando target=domínio).
- Relatório HTML com etapas, aplicações, serviços/portas e vulnerabilidades (CVSS básico).
