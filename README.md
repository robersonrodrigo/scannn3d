# scannn3d

Plataforma ofensiva em Go para descoberta, varredura web/API, recon, orquestracao de pentest e geracao de relatorios.

## Componentes principais

- `cmd/platform-api`: API REST com interface web embarcada.
- `cmd/platform-cli`: CLI para disparo e consulta de scans.
- `internal/platform/recon`: descoberta de subdominios e recon.
- `internal/platform/pentest`: orquestracao segura de ferramentas como Dirsearch, FFUF, Nuclei e Nmap.
- `internal/platform/report`: geracao de relatorios JSON e HTML.

## Requisitos

- Go 1.22+
- Docker e Docker Compose (opcional)

## Execucao local

```bash
cp .env.example .env
# edite .env antes de iniciar
go run ./cmd/platform-api
```

Variaveis importantes:

- `PLATFORM_JWT_SECRET`: obrigatoria, com pelo menos 32 caracteres.
- `PLATFORM_ADMIN_PASSWORD`: define a senha inicial do admin.
- `PLATFORM_DB_DRIVER` e `PLATFORM_DB_DSN`: configuram SQLite ou PostgreSQL.

O binario `platform-api` carrega automaticamente o arquivo `.env` na raiz do projeto quando ele existe.

Exemplo para gerar um secret forte:

```bash
openssl rand -hex 32
```

## Execucao com Docker

```bash
cp .env.example .env
# edite .env antes de subir
docker compose up -d --build platform-api
```

Aplicacao padrao:

```text
http://localhost:8095
```

## Documentacao adicional

- [MVP da plataforma](docs/PLATFORM_MVP.md)
- [Docker Compose](docs/DOCKER_COMPOSE.md)
- [Analise de arquitetura](docs/ANALISE_ARQUITETURA.md)
- [Modulo de recon](docs/recon-module.md)
