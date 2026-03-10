
```text
                                  ____      _
                                |___ \    | |
 ___  ___ __ _ _ __  _ __  _ __   __) | __| |
/ __|/ __/ _` | '_ \| '_ \| '_ \ |__ < / _` |
\__ \ (_| (_| | | | | | | | | | |___) | (_| |
|___/\___\__,_|_| |_|_| |_|_| |_|____/ \__,_|
```

Plataforma ofensiva em Go para descoberta de superficie de ataque, varredura web/API, recon modular, orquestracao de pentest e geracao de relatorios.

## Visao geral

O `scannn3d` combina uma API REST, uma interface web embarcada e uma CLI tecnica para centralizar fluxos comuns de AppSec e offensive security:

- descoberta e validacao de alvos
- scans web/API e infraestrutura
- recon por pipeline com cache
- orquestracao controlada de ferramentas externas
- correlacao de ativos, servicos, vulnerabilidades e cadeias de ataque
- exportacao de relatorios HTML, JSON e artefatos TXT

O projeto esta organizado como uma plataforma unica, com foco em:

- operacao local ou via Docker
- distribuicao simples
- execucao concorrente controlada
- auditoria e historico de eventos
- acoplamento baixo entre modulos

## Principais capacidades

- `Platform API + UI`: backend HTTP com interface web embarcada em `cmd/platform-api`
- `CLI tecnica`: cliente leve para login, disparo de scans e listagem em `cmd/platform-cli`
- `Recon pipeline`: `subfinder`, `alterx`, resolucao DNS, portas, probing HTTP, crawling e fontes opcionais como `chaos`, `uncover` e `cloudlist`
- `Scan web/API`: fingerprint, validacao de headers, XSS, SQLi, SSRF, JWT, BOLA, command injection, SSTI, open redirect, path traversal/LFI, CORS, metodos inseguros e checks basicos de TLS
- `Scan de infraestrutura`: varredura TCP e fingerprint de portas/servicos
- `Pentest jobs`: execucao segura de `dirsearch`, `ffuf`, `nuclei` e `nmap`, com validacao de argumentos, timeout, stop/cancel e trilha de auditoria
- `Relatorios`: saida HTML e JSON por scan, mais artefatos TXT por job de pentest
- `Observabilidade`: SSE, WebSocket, `events.log`, `audit.log` e status detalhado por etapa

## Arquitetura resumida

Componentes principais:

- `cmd/platform-api`: API REST, autenticacao, UI embarcada e roteamento principal
- `cmd/platform-cli`: CLI para login e operacao de scans
- `internal/platform/orchestration`: pipeline de scans e persistencia de resultados
- `internal/platform/recon`: jobs de recon, eventos e cache local
- `internal/platform/pentest`: fila de jobs, controle de concorrencia, auditoria e adaptadores de ferramentas
- `internal/platform/storage`: armazenamento `in-memory`, SQLite e PostgreSQL
- `internal/platform/report`: geracao de `platform-report.json` e `platform-report.html`
- `internal/scanners`: scanners web/API e templates internos

Entrada oficial do produto:

- `platform-api` para web e API
- `platform-cli` para operacao via terminal

Binarios legados:

- `cmd/scannn3d`
- `cmd/scannn3d-ui`

Esses binarios permanecem por compatibilidade, mas o fluxo recomendado e a plataforma unificada.

## Fluxos suportados

### 1. Scan web/API

Pipeline atual:

1. fingerprint de WAF com `wafw00f`
2. fingerprint de tecnologias com `whatweb`
3. portas e servicos com `nmap top-100`
4. modulos web/API
5. correlacao, persistencia e relatorios

### 2. Recon

Pipeline padrao de recon:

1. `asnmap` quando um ASN e informado
2. `subfinder`
3. `alterx`
4. resolucao DNS
5. `naabu`
6. probing HTTP
7. `katana`
8. `chaos` e `uncover` como fontes opcionais
9. `cloudlist` como fonte opcional

Saida consolidada:

- dominios
- subdominios
- IPs
- portas
- URLs

### 3. Pentest jobs

Modos suportados:

- `module=web`: `dirsearch`, `ffuf`, `nuclei`
- `module=infra`: `nmap`
- `target_type=auto|url|ip`

Caracteristicas operacionais:

- execucao sem shell com `exec.CommandContext`
- allowlist de argumentos customizados por ferramenta
- limite de concorrencia global
- timeout por ferramenta
- artefatos por job
- historico de eventos
- stop/cancel por API

## Requisitos

- Go `1.22+`
- Docker e Docker Compose para o fluxo containerizado
- ambiente Linux recomendado para o stack completo

Dependendo do modo de uso, o projeto tambem pode precisar de ferramentas externas disponiveis no `PATH`.

## Quick start local

### 1. Preparar variaveis

```bash
cp .env.example .env
```

Edite o `.env` e substitua os placeholders obrigatorios:

- `PLATFORM_JWT_SECRET`
- `PLATFORM_ADMIN_PASSWORD`
- `POSTGRES_PASSWORD` se for usar Compose/PostgreSQL

Gerar um secret forte:

```bash
openssl rand -hex 32
```

O binario `platform-api` carrega automaticamente o arquivo `.env` na raiz do projeto, sem precisar fazer `source`.

### 2. Subir a API

```bash
go run ./cmd/platform-api
```

Abrir no navegador:

```text
http://localhost:8095
```

Usuario inicial:

- `admin`

Senha inicial:

- definida por `PLATFORM_ADMIN_PASSWORD`
- se a variavel nao existir, a aplicacao gera uma senha aleatoria e registra no log
- se ja existir usuario no banco, o seed nao e recriado

### 3. Armazenamento

Modos suportados:

- `in-memory`: usado quando nenhum banco e configurado
- `sqlite`: quando `PLATFORM_DB_DRIVER=sqlite` ou `PLATFORM_DB_DSN` estiver definido
- `postgres`: quando `PLATFORM_DB_DRIVER=postgres` ou `PLATFORM_DB_DSN` apontar para PostgreSQL

Para testes rapidos locais, `in-memory` funciona bem. Para persistencia real, use SQLite ou PostgreSQL.

## Quick start com Docker Compose

```bash
cp .env.example .env
# edite os placeholders antes de subir
docker compose up -d --build platform-api
```

Abrir:

```text
http://localhost:8095
```

Ver logs:

```bash
docker compose logs -f platform-api
```

Parar:

```bash
docker compose down
```

O Compose padrao sobe:

- `platform-api`
- `postgres`
- `pgbouncer`

Perfis opcionais:

- `cli`
- `external`
- `recon`

Exemplos:

```bash
docker compose --profile cli run --rm platform-cli --help
docker compose --profile external up -d zap metasploit
```

## Variaveis de ambiente principais

| Variavel | Obrigatoria | Descricao |
|---|---|---|
| `PLATFORM_JWT_SECRET` | sim | segredo JWT com pelo menos 32 caracteres |
| `PLATFORM_ADMIN_PASSWORD` | recomendada | senha inicial do admin; placeholders sao rejeitados |
| `PLATFORM_LISTEN` | nao | endereco HTTP, padrao `:8095` |
| `PLATFORM_DB_DRIVER` | nao | `sqlite` ou `postgres` |
| `PLATFORM_DB_DSN` | nao | DSN do banco configurado |
| `PLATFORM_REPORTS_DIR` | nao | diretorio base de saida, padrao `./platform-runs` |
| `PLATFORM_RECON_CACHE_DSN` | nao | arquivo de cache do recon, padrao `platform-runs/recon-cache.json` |
| `PLATFORM_TEMPLATES_DIR` | nao | diretorio de templates internos |
| `PLATFORM_CORS_ALLOWED_ORIGINS` | nao | allowlist CORS separada por virgula |
| `PENTEST_MAX_CONCURRENT_JOBS` | nao | limite de jobs paralelos |
| `PENTEST_MAX_THREADS` | nao | teto de threads por job de pentest |

## Uso da CLI

Ajuda:

```bash
go run ./cmd/platform-cli --help
```

Listar scans:

```bash
PLATFORM_PASSWORD='sua-senha' \
go run ./cmd/platform-cli --list
```

Rodar scan completo:

```bash
PLATFORM_PASSWORD='sua-senha' \
go run ./cmd/platform-cli \
  --target https://example.com \
  --full
```

Opcoes relevantes:

- `--api`: URL base da API, padrao `http://127.0.0.1:8095`
- `--user`: usuario, padrao `admin`
- `--pass`: senha da conta
- `--target`: alvo URL ou host
- `--infra`: scan de infraestrutura
- `--web`: scan web
- `--full`: scan completo
- `--list`: listar scans existentes

## Exemplos de API

### Login

```bash
curl -X POST http://127.0.0.1:8095/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"SUA_SENHA"}'
```

### Criar scan

```bash
curl -X POST http://127.0.0.1:8095/api/v1/scans \
  -H "Authorization: Bearer <JWT>" \
  -H 'Content-Type: application/json' \
  -d '{
    "target":"https://example.com",
    "mode":"full"
  }'
```

### Criar recon job

```bash
curl -X POST http://127.0.0.1:8095/api/v1/recon/jobs \
  -H "Authorization: Bearer <JWT>" \
  -H 'Content-Type: application/json' \
  -d '{
    "target":"example.com",
    "modules":["pipeline"],
    "options":{"use_chaos":true,"use_uncover":true}
  }'
```

### Criar pentest job web

```bash
curl -X POST http://127.0.0.1:8095/api/v1/pentest/jobs \
  -H "Authorization: Bearer <JWT>" \
  -H 'Content-Type: application/json' \
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

## Rotas principais

Autenticacao:

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `GET /api/v1/auth/me`
- `POST /api/v1/auth/change-password`

Scans e ativos:

- `POST /api/v1/scans`
- `POST /api/v1/scans/preflight`
- `GET /api/v1/scans`
- `GET /api/v1/scans/{id}`
- `GET /api/v1/targets`
- `GET /api/v1/vulnerabilities`
- `GET /api/v1/graphs/targets/{targetId}`
- `GET /api/v1/chains/targets/{targetId}`

Recon:

- `POST /api/v1/recon/jobs`
- `GET /api/v1/recon/jobs`
- `GET /api/v1/recon/jobs/{id}`
- `GET /api/v1/recon/jobs/{id}/result`
- `GET /api/v1/recon/jobs/{id}/events`
- `GET /api/v1/recon/jobs/{id}/events/history`
- `POST /api/v1/recon/jobs/{id}/rerun`

Pentest:

- `POST /api/v1/pentest/jobs`
- `GET /api/v1/pentest/jobs`
- `GET /api/v1/pentest/jobs/{id}`
- `POST /api/v1/pentest/jobs/{id}/stop`
- `GET /api/v1/pentest/jobs/{id}/events`
- `GET /api/v1/pentest/jobs/{id}/events/history`
- `GET /api/v1/pentest/jobs/{id}/report.txt`
- `GET /api/v1/pentest/ws/{id}?since=0`

Relatorios:

- `GET /api/v1/reports/scans/{scanId}.json`
- `GET /api/v1/reports/scans/{scanId}.html`

## Artefatos gerados

Saidas de scans:

- `platform-runs/<scan-id>/events.log`
- `platform-runs/<scan-id>/platform-report.json`
- `platform-runs/<scan-id>/platform-report.html`
- artefatos auxiliares como `subfinder.txt`, `wafw00f.log`, `whatweb.log` e `nmap.log/xml`

Saidas de pentest:

- `platform-runs/pentest/YYYY-MM-DD/<target>/<job-id>/summary.txt`
- `platform-runs/pentest/YYYY-MM-DD/<target>/<job-id>/dirsearch.txt`
- `platform-runs/pentest/YYYY-MM-DD/<target>/<job-id>/ffuf.txt`
- `platform-runs/pentest/YYYY-MM-DD/<target>/<job-id>/nuclei.txt`
- `platform-runs/pentest/YYYY-MM-DD/<target>/<job-id>/nmap.txt`
- `platform-runs/pentest/audit.log`

Cache de recon:

- `platform-runs/recon-cache.json` por padrao

## Ferramentas externas

Incluidas na imagem principal:

- `subfinder`
- `ffuf`
- `nuclei`
- `nmap`
- `sqlmap`
- `wapiti`
- `whatweb`
- `dirsearch`
- `wafw00f`

Disponiveis como sidecar ou perfil opcional:

- `OWASP ZAP`
- `Metasploit`

Observacao operacional:

- a plataforma detecta binarios em tempo de execucao
- ausencia de uma ferramenta nao derruba todo o pipeline; o modulo correspondente falha e o job continua quando possivel

## Seguranca e operacao

Pontos importantes:

- use a ferramenta apenas em ativos sob sua autorizacao
- segredos placeholder sao rejeitados no bootstrap
- `access_token` e `refresh_token` sao distintos
- jobs de pentest retornam respostas sanitizadas para evitar vazamento de comandos, caminhos internos e argumentos sensiveis
- CORS pode ser restringido com `PLATFORM_CORS_ALLOWED_ORIGINS`

## Limitacoes atuais

- o projeto ainda esta em fase de MVP/iteracao continua
- varios modulos dependem de binarios externos no ambiente
- algumas ferramentas pesadas funcionam melhor em sidecars dedicados
- os binarios legados existem por compatibilidade, mas o fluxo principal e `platform-api` + `platform-cli`

## Estrutura do repositorio

```text
cmd/
  platform-api/
  platform-cli/
  scannn3d/
  scannn3d-ui/
docs/
internal/
docker/
docker-compose.yml
Dockerfile
```

## Documentacao adicional

- [MVP da plataforma](docs/PLATFORM_MVP.md)
- [Docker Compose](docs/DOCKER_COMPOSE.md)
- [Analise de arquitetura](docs/ANALISE_ARQUITETURA.md)
- [Modulo de recon](docs/recon-module.md)
