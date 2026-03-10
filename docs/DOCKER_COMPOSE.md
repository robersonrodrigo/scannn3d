# Docker Compose

## Subir a plataforma (entrada unica)

```bash
docker compose up --build -d platform-api
```

Abrir:

```text
http://localhost:8095
```

Relatorios e logs:
```
./platform-runs/<scan-id>/
  - events.log
  - platform-report.json
  - platform-report.html
./platform-runs/pentest/YYYY-MM-DD/<target>/<job-id>/
  - summary.txt
  - dirsearch.txt / ffuf.txt / nuclei.txt / nmap.txt
  - events.log
./platform-runs/pentest/
  - audit.log
```

## Ver logs

```bash
docker compose logs -f platform-api
```

## Parar

```bash
docker compose down
```

## Rodar CLI via compose (perfil opcional)

Ajuda:

```bash
docker compose --profile cli run --rm platform-cli --help
```

Exemplo scan:

```bash
docker compose --profile cli run --rm platform-cli \
  --target https://api.example.com \
  --full
```

## Perfis de ferramentas externas (sidecars)

Algumas ferramentas pesadas rodam melhor em containers dedicados.

```bash
docker compose --profile external up -d zap metasploit
```

Ferramentas instaladas na imagem principal:
- nmap, ffuf, nuclei, sqlmap, wapiti, whatweb, dirsearch (venv), wafw00f (venv best-effort), subfinder (build stage copiado).

Observacao:
- A entrada oficial unica do produto e `platform-api`.
- Binarios `scannn3d-ui` e `scannn3d` permanecem apenas por compatibilidade e estao deprecados.
