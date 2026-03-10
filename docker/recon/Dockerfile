FROM golang:1.24-bookworm AS tools

RUN set -eux; \
  GOBIN=/out go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; \
  GOBIN=/out go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest; \
  GOBIN=/out go install github.com/projectdiscovery/katana/cmd/katana@latest; \
  GOBIN=/out go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest || true; \
  GOBIN=/out go install github.com/projectdiscovery/uncover/cmd/uncover@latest || true; \
  GOBIN=/out go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest || true; \
  GOBIN=/out go install github.com/projectdiscovery/alterx/cmd/alterx@latest || true; \
  GOBIN=/out go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest || true

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates curl dnsutils && rm -rf /var/lib/apt/lists/*

COPY --from=tools /out/ /usr/local/bin/

RUN useradd -m -d /app appuser
USER appuser
WORKDIR /app

ENTRYPOINT ["sh", "-c", "sleep infinity"]
