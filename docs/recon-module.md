# Recon Module (MVP)

## Overview
The Platform API now exposes a dedicated recon pipeline service under `/api/v1/recon/jobs`.

Pipeline (default `modules=["pipeline"]`):
1. `asnmap` (if `asn` provided)
2. `subfinder`
3. `alterx`
4. `dns_resolution`
5. `naabu`
6. `http_probe`
7. `katana`
8. `chaos` and `uncover` (opt-in)
9. `cloudlist` (opt-in)

All module outputs are normalized into a unified JSON schema containing:
- domains
- subdomains
- ips
- ports
- urls

## API
### Create job
`POST /api/v1/recon/jobs`

```json
{
  "target": "example.com",
  "asn": "",
  "modules": ["pipeline"],
  "options": {
    "ports": "top-100",
    "custom_ports": "",
    "use_cloudlist": false,
    "use_chaos": true,
    "use_uncover": true,
    "force": false
  }
}
```

### List jobs
`GET /api/v1/recon/jobs`

### Get job
`GET /api/v1/recon/jobs/{id}`

### Get result
`GET /api/v1/recon/jobs/{id}/result`

### Events (SSE)
`GET /api/v1/recon/jobs/{id}/events?since=0`

### Events history
`GET /api/v1/recon/jobs/{id}/events/history?since=0`

### Rerun (cache bypass)
`POST /api/v1/recon/jobs/{id}/rerun`

## Cache
- Backend: SQLite (`modernc.org/sqlite`)
- Env: `PLATFORM_RECON_CACHE_DSN`
- Default: `file:platform-runs/recon-cache.db?cache=shared`
- TTL per module:
  - 8h: `subfinder`, `naabu`, `katana`, `chaos`, `uncover`
  - 24h: `asnmap`, `cloudlist`

## Execution Notes
- Modules are isolated by adapter and can fail independently.
- Tool binaries are detected at runtime via `exec.LookPath`.
- Missing tools produce module failure status while the pipeline continues.

## Example Run
```bash
export PLATFORM_ADMIN_PASSWORD='defina-uma-senha-forte'

TOKEN=$(curl -s -X POST http://127.0.0.1:8095/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${PLATFORM_ADMIN_PASSWORD}\"}" | jq -r .access_token)

JOB=$(curl -s -X POST http://127.0.0.1:8095/api/v1/recon/jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","modules":["pipeline"],"options":{"use_chaos":true,"use_uncover":true}}' | jq -r .id)

curl -N -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8095/api/v1/recon/jobs/${JOB}/events?since=0"
```
