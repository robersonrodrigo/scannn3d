FROM golang:1.22-bookworm AS builder

WORKDIR /src

# Cache dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Install external tools in a separate layer to avoid re-downloading on code changes
RUN GOBIN=/out go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6 && \
    GOBIN=/out go install github.com/ffuf/ffuf/v2@v2.1.0 && \
    GOBIN=/out go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.0

# Copy source and build internal components
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/scannn3d ./cmd/scannn3d && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/scannn3d-ui ./cmd/scannn3d-ui && \
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o /out/platform-api ./cmd/platform-api && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/platform-cli ./cmd/platform-cli

FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl python3 python3-pip python3-venv ruby-full nmap sqlmap wapiti whatweb \
    && rm -rf /var/lib/apt/lists/*

# Install dirsearch in isolated virtualenv to avoid PEP-668 and keep runtime clean.
RUN python3 -m venv /opt/dirsearch-venv \
    && /opt/dirsearch-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/dirsearch-venv/bin/pip install --no-cache-dir dirsearch \
    && printf '#!/bin/sh\nexec /opt/dirsearch-venv/bin/dirsearch \"$@\"\n' > /usr/local/bin/dirsearch \
    && chmod +x /usr/local/bin/dirsearch

# Install wafw00f best-effort (tolerate failure)
RUN python3 -m venv /opt/wafw00f-venv \
    && /opt/wafw00f-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/wafw00f-venv/bin/pip install --no-cache-dir wafw00f \
    && printf '#!/bin/sh\nexec /opt/wafw00f-venv/bin/wafw00f \"$@\"\n' > /usr/local/bin/wafw00f \
    && chmod +x /usr/local/bin/wafw00f || true

# Best-effort placeholders for tools that are often deployed as dedicated services.
RUN printf '#!/bin/sh\n>&2 echo \"msfconsole is not bundled in this image; use metasploit sidecar/profile.\"\nexit 2\n' > /usr/local/bin/msfconsole && chmod +x /usr/local/bin/msfconsole
RUN printf '#!/bin/sh\n>&2 echo \"arachni is not bundled in this image; install custom arachni image if needed.\"\nexit 2\n' > /usr/local/bin/arachni && chmod +x /usr/local/bin/arachni
RUN printf '#!/bin/sh\n>&2 echo \"vega CLI is not bundled in this image.\"\nexit 2\n' > /usr/local/bin/vega && chmod +x /usr/local/bin/vega
RUN printf '#!/bin/sh\n>&2 echo \"OWASP ZAP is not bundled in this image; use zap sidecar/profile.\"\nexit 2\n' > /usr/local/bin/zaproxy && chmod +x /usr/local/bin/zaproxy
RUN printf '#!/bin/sh\n>&2 echo \"OWASP ZAP baseline script is not bundled in this image; use zap sidecar/profile.\"\nexit 2\n' > /usr/local/bin/zap-baseline.py && chmod +x /usr/local/bin/zap-baseline.py
RUN printf '#!/bin/sh\n>&2 echo \"nikto is not bundled in this image; install nikto in custom image or sidecar.\"\nexit 2\n' > /usr/local/bin/nikto && chmod +x /usr/local/bin/nikto
RUN printf '#!/bin/sh\n>&2 echo \"wpscan is not bundled in this image; install wpscan in custom image or sidecar.\"\nexit 2\n' > /usr/local/bin/wpscan && chmod +x /usr/local/bin/wpscan

RUN useradd -m -d /app appuser
WORKDIR /app

COPY --from=builder /out/scannn3d /usr/local/bin/scannn3d
COPY --from=builder /out/scannn3d-ui /usr/local/bin/scannn3d-ui
COPY --from=builder /out/platform-api /usr/local/bin/platform-api
COPY --from=builder /out/platform-cli /usr/local/bin/platform-cli
COPY --from=builder /out/subfinder /usr/local/bin/subfinder
COPY --from=builder /out/ffuf /usr/local/bin/ffuf
COPY --from=builder /out/nuclei /usr/local/bin/nuclei

RUN mkdir -p /data/runs /data/platform-runs && chown -R appuser:appuser /data /app
USER appuser

EXPOSE 8095
ENTRYPOINT ["platform-api"]
