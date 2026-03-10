# Análise Técnica, Decisão de Linguagem e Arquitetura - scannn3d

## ETAPA 1 - Análise de Mercado

### 1) Burp Suite
- Linguagem: Java (core e ecossistema de extensão Montoya API em Java).
- Performance: boa para workload de proxy/scanner com tuning de heap JVM.
- Concorrência: robusta (threads da JVM), com paralelismo maduro.
- Extensão: alta, via BApp Store, API de extensão e scripts/BChecks.
- Ecossistema: muito forte em AppSec web.
- Curva de aprendizado: média/alta (stack rica, recursos avançados).
- Portabilidade: alta (Windows/Linux/macOS, empacotamento com runtime Java).
- Segurança da linguagem: Java memory-safe por design de VM.
- Memória: GC da JVM (trade-off entre throughput, latência e consumo).
- Networking baixo nível: bom (HTTP/TLS avançado na plataforma Java).

### 2) OWASP ZAP
- Linguagem: Java/Kotlin (core com add-ons e scripting).
- Performance: boa, porém dependente de tuning de JVM e add-ons ativos.
- Concorrência: alta (multi-threading da JVM).
- Extensão: muito alta (add-ons, scripts, automação).
- Ecossistema: forte e open source, foco em AppSec web.
- Curva de aprendizado: média.
- Portabilidade: alta (JVM multiplataforma).
- Segurança da linguagem: memory-safe na VM.
- Memória: GC.
- Networking baixo nível: bom para casos de DAST/proxy HTTP(S).

### 3) Nmap
- Linguagem: C/C++ (core de scanning de rede).
- Performance: excelente para low-level networking e throughput elevado.
- Concorrência: alta, altamente otimizado.
- Extensão: NSE (Lua) aumenta flexibilidade.
- Ecossistema: muito consolidado.
- Curva de aprendizado: média (uso básico) / alta (NSE avançado).
- Portabilidade: muito alta.
- Segurança da linguagem: C/C++ sem memory safety intrínseca.
- Memória: manual.
- Networking baixo nível: excelente (raw sockets, packet crafting).

### 4) Metasploit
- Linguagem: Ruby (framework), com componentes em outras linguagens.
- Performance: adequada para orquestração/exploração, não focada em throughput bruto.
- Concorrência: razoável.
- Extensão: muito alta (módulos/plugins).
- Ecossistema: vasto em offensive security.
- Curva de aprendizado: média/alta.
- Portabilidade: alta.
- Segurança da linguagem: melhor que C para memory corruption, mas runtime dinâmico.
- Memória: GC.
- Networking baixo nível: bom para framework de exploração, menos para ultra performance.

### 5) Nikto
- Linguagem: Perl.
- Performance: moderada (scanner clássico baseado em assinaturas).
- Concorrência: limitada comparada a arquiteturas modernas.
- Extensão: razoável por plugins/assinaturas.
- Ecossistema: estável, legado útil.
- Curva de aprendizado: baixa/média.
- Portabilidade: alta.
- Segurança da linguagem: sem classe de bug de memória de C, mas runtime legado.
- Memória: GC/refcount do runtime Perl.
- Networking baixo nível: suficiente ao propósito, não otimizado para escala massiva.

### 6) Gobuster
- Linguagem: Go.
- Performance: alta para bruteforce de diretórios/DNS/vhost.
- Concorrência: excelente (goroutines + canais).
- Extensão: moderada (arquitetura mais focada em casos específicos).
- Ecossistema: forte em tooling de segurança moderno.
- Curva de aprendizado: baixa/média.
- Portabilidade: excelente (binário único estático em muitos cenários).
- Segurança da linguagem: memory-safe em geral.
- Memória: GC com overhead previsível para I/O-bound.
- Networking baixo nível: muito bom no stack padrão + libs do ecossistema.

### 7) SQLMap
- Linguagem: Python.
- Performance: boa para automação especializada de SQLi; menor throughput bruto que Go/Rust.
- Concorrência: limitada pelo modelo do Python tradicional (com melhorias recentes em free-threaded build ainda não padrão).
- Extensão: muito alta (scripts, tamper, plugins).
- Ecossistema: fortíssimo em AppSec scripting.
- Curva de aprendizado: baixa/média.
- Portabilidade: alta.
- Segurança da linguagem: memory-safe no nível da linguagem.
- Memória: GC/refcount.
- Networking baixo nível: bom para HTTP tooling, menos eficiente em alto volume extremo.

### 8) Postman (contexto APIs)
- Linguagem/runtime: ecossistema fortemente Node.js/JavaScript (Runtime open source).
- Performance: boa para testes funcionais e automação de coleções.
- Concorrência: modelo assíncrono de event loop eficiente para I/O.
- Extensão: alta no ecossistema de scripts/collections.
- Ecossistema: enorme em API lifecycle.
- Curva de aprendizado: baixa.
- Portabilidade: alta.
- Segurança da linguagem: memory-safe no nível de runtime JS.
- Memória: GC.
- Networking baixo nível: bom para API testing, menos orientado a scanning ofensivo de alta escala.

### 9) Ferramentas modernas escritas em Go
- Exemplos: ProjectDiscovery Nuclei e httpx.
- Características observadas: foco em alta concorrência, UX CLI forte, distribuição simples via binário único, integração fácil em pipelines CI/CD.
- Trade-off: para parsing/extensibilidade dinâmica extrema, linguagens mais dinâmicas podem iterar mais rápido em scripts; porém Go equilibra velocidade e mantenibilidade para produtos de scanner.

---

## ETAPA 2 - Critérios Técnicos de Decisão

### Critérios objetivos
1. Performance sob alta concorrência I/O-bound.
2. Velocidade de desenvolvimento para MVP e evolução contínua.
3. Ecossistema de segurança (HTTP, fuzzing, parsing, templates).
4. Binário standalone multiplataforma.
5. Segurança da linguagem (memory safety).
6. Qualidade de CLI e observabilidade (logging, tracing, métricas).
7. Escalabilidade futura (módulos/plugins e manutenção por equipe).
8. Comunidade ativa e adoção corporativa.
9. Suporte corporativo e contratação de talentos.

### Matriz comparativa (1-5)

| Critério | Python | Go | Rust | Java | Node.js |
|---|---:|---:|---:|---:|---:|
| Alta concorrência | 3 | 5 | 5 | 4 | 4 |
| Velocidade de desenvolvimento | 5 | 4 | 2 | 3 | 4 |
| Ecossistema AppSec | 5 | 4 | 3 | 4 | 4 |
| Binário standalone | 2 | 5 | 5 | 2 | 2 |
| Memory safety | 4 | 4 | 5 | 4 | 4 |
| CLI profissional | 4 | 5 | 4 | 4 | 4 |
| Escalabilidade de código | 3 | 5 | 4 | 5 | 3 |
| Plugins/modularidade | 5 | 4 | 3 | 5 | 4 |
| Comunidade ativa | 5 | 5 | 4 | 5 | 5 |
| Adoção corporativa | 5 | 5 | 4 | 5 | 5 |
| **Total** | **41** | **46** | **39** | **41** | **39** |

### Vantagens e desvantagens reais

#### Python
- Vantagens: velocidade de prototipação, enorme ecossistema AppSec (sqlmap-like workflows).
- Desvantagens: throughput/concurrency inferior para scanner massivo; distribuição mais complexa (runtime + deps).

#### Go
- Vantagens: ótimo custo-benefício entre performance, simplicidade, concorrência nativa e deploy em binário único.
- Desvantagens: plugin dinâmico cross-platform menos trivial; GC exige disciplina em alocação para picos extremos.

#### Rust
- Vantagens: performance máxima com memory safety forte.
- Desvantagens: curva de aprendizado e tempo de desenvolvimento maiores, especialmente para times mistos.

#### Java
- Vantagens: maturidade enterprise, tooling robusto, concorrência forte (incluindo virtual threads).
- Desvantagens: distribuição mais pesada (JVM), DX menos direta para ferramenta CLI leve.

#### Node.js
- Vantagens: produtividade alta para APIs, ecossistema enorme.
- Desvantagens: CPU-bound e paralelismo exigem gestão de workers; robustez de scanner de alta carga tende a demandar engenharia extra.

---

## ETAPA 3 - Decisão Justificada

### Linguagem escolhida: Go

Justificativa técnica:
1. Entrega o melhor equilíbrio entre desempenho de scanner concorrente e velocidade de implementação.
2. Modelo de concorrência (goroutines/channels) simplifica arquitetura paralela sem overhead operacional de processo por worker.
3. Distribuição corporativa simples: binário único, fácil de rodar em CI/CD, containers e ambientes restritos.
4. Memory safety superior a C/C++ para reduzir classes de falhas críticas no próprio scanner.
5. Tendência de mercado em segurança ofensiva/defensiva moderna mostra forte adoção de ferramentas em Go.
6. Manutenibilidade alta para times AppSec/Platform (código legível, compile-time checks, tooling padrão).

---

## ETAPA 4 - Arquitetura da Ferramenta

### Arquitetura modular (implementada)
- `cmd/scannn3d`: entrada CLI.
- `internal/core`: engine, contratos (`Scanner`, `TargetRequest`, `Finding`).
- `internal/request`: request manager central (scope, auth, rate-limit, timeout, TLS).
- `internal/scanners`: módulos de detecção (SQLi, XSS, SSRF, JWT, BOLA).
- `internal/report`: geração de relatório JSON/HTML.
- `internal/logging`: logging estruturado auditável.
- `internal/scope`: controle de escopo por host allowlist.
- `internal/auth`: aplicação de autenticação (none/bearer/basic/apikey).
- `internal/ratelimit`: token bucket interno.

### Padrões aplicados
- Strategy: cada scanner implementa interface comum.
- Registry/Factory: seleção de scanners por nome.
- Facade: `RequestManager` centraliza cross-cutting concerns.
- Pipeline orientado a workers: engine concorrente com limite de paralelismo.

### Decisões arquiteturais chave
1. Segurança by default: controle de escopo obrigatório + banner ético.
2. Concorrência controlada: semáforo no engine e rate limiter no transporte.
3. Observabilidade: logs JSON auditáveis (stdout + arquivo).
4. Extensibilidade: adicionar novo scanner = novo arquivo implementando interface.

---

## ETAPA 5 - Implementação (Resumo)

Implementado e compilando:
- Core Engine concorrente.
- Request Manager com timeout/TLS/auth/scope/rate-limit.
- Scanners Web/API: `wafw00f`, `whatweb`, `nmap top-100`, `sqli`, `xss`, `ssrf`, `jwt`, `bola`, `command injection`, `ssti`, `open redirect`, `path traversal/LFI`, headers de segurança, métodos inseguros, verificação de versão TLS.
- CLI profissional via flags e validações.
- Relatórios `report.json` e `report.html`.
- Logging estruturado (`audit.log`).
- UI: wizard de novo scan, terminal em tempo real, tabela de etapas (`step_results`), listagem de subdomínios, download de relatórios.
- Step Results: cada etapa (wafw00f, whatweb, nmap, webscan) registrada com status/resumo/evidência; exposta via API/UI/relatório.

## Estado Atual (Fev/2026)
- Pipeline URL: wafw00f → whatweb → nmap top-100 → módulos Web/API.
- Recon: subfinder + validação de subdomínios e alvo web.
- Observabilidade: SSE + logs JSON + arquivos `events.log`.
- Relatórios: HTML/JSON incluem etapas, aplicações, serviços/portas, vulnerabilidades com CVSS básico e cadeia de ataque.

---

## ETAPA 6 - Segurança e Ética

Controles implementados:
1. Banner de uso ético obrigatório na inicialização.
2. Scope control por host allowlist (bloqueia alvo fora de escopo).
3. Rate limiting interno (token bucket).
4. Tratamento robusto de erros por módulo, sem crash global.
5. Logs auditáveis estruturados para rastreabilidade.

---

## ETAPA 7 - Output Esperado

### Estrutura de diretórios

```text
scannn3d/
  cmd/scannn3d/main.go
  internal/
    auth/auth.go
    config/config.go
    core/{engine.go,types.go}
    logging/logger.go
    ratelimit/limiter.go
    report/report.go
    request/manager.go
    scanners/{registry.go,common.go,sqli.go,xss.go,ssrf.go,jwt.go,bola.go}
    scope/scope.go
  docs/ANALISE_ARQUITETURA.md
  go.mod
```

### Dependências
- Projeto implementado apenas com biblioteca padrão Go (sem dependências externas).

### Exemplo de execução

```bash
go run ./cmd/scannn3d \
  --target https://api.exemplo.com \
  --endpoints '/v1/users?id=1,/v1/orders?id=10' \
  --modules sqli,xss,ssrf,jwt,bola \
  --auth-type bearer --auth-token '<TOKEN>' \
  --scope-hosts api.exemplo.com \
  --rate 20 --burst 20 --concurrency 8 \
  --format both --output ./out
```

### Exemplo de output (resumido)

```text
[ETHICAL USE REQUIRED] This tool is authorized testing only.
...
{"level":"INFO","msg":"scan_started","module":"sqli","target":"https://api.exemplo.com/v1/users?id=1"}
{"level":"INFO","msg":"report_written","format":"json","path":"out/report.json"}
{"level":"INFO","msg":"report_written","format":"html","path":"out/report.html"}
Findings: 3
```

---

## Referências técnicas
- Burp extension development (Java/Montoya): https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating
- Burp runtime/JAR e Java mínimo: https://portswigger.net/support/launching-burp-suite-from-the-command-line
- OWASP ZAP repo: https://github.com/zaproxy/zaproxy
- ZAP Java requirements: https://www.zaproxy.org/faq/what-versions-of-java-are-supported/
- Nmap repo: https://github.com/nmap/nmap
- Metasploit repo: https://github.com/rapid7/metasploit-framework
- Nikto repo: https://github.com/sullo/nikto
- Gobuster repo (Go): https://github.com/OJ/gobuster
- SQLMap repo: https://github.com/sqlmapproject/sqlmap
- Postman Runtime docs (Node.js): https://learning.postman.com/docs/developer/runtime-library/
- Postman Runtime npm: https://www.npmjs.com/package/postman-runtime
- Nuclei repo (Go): https://github.com/projectdiscovery/nuclei
- httpx repo (Go): https://github.com/projectdiscovery/httpx
- Python threading/GIL: https://docs.python.org/3/library/threading.html
- Python free-threading status: https://docs.python.org/3/howto/free-threading-python.html
- Node worker_threads: https://nodejs.org/api/worker_threads.html
- Go Effective Go (concurrency): https://go.dev/doc/effective_go
- Go race detector/memory model reference: https://go.dev/doc/articles/race_detector.html
- Rust concurrency (book): https://doc.rust-lang.org/book/ch16-00-concurrency.html
- Rust ownership/memory safety: https://doc.rust-lang.org/beta/nomicon/ownership.html
- Java virtual threads (JDK 21): https://docs.oracle.com/en/java/javase/21/core/virtual-threads.html
- Stack Overflow Developer Survey 2024 (technology): https://survey.stackoverflow.co/2024/technology/
- GitHub Octoverse 2024: https://github.blog/news-insights/octoverse/octoverse-2024/
- GitHub Octoverse 2025 update: https://github.blog/news-insights/octoverse/octoverse-a-new-developer-joins-github-every-second-as-ai-leads-typescript-to-1/
