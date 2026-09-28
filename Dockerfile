# syntax=docker/dockerfile:1
# Harbor Scanner Grype, built from source.
#   docker build -t ant1freeze/harbor-scanner-grype:latest .
#   docker buildx build --platform linux/amd64 -t ant1freeze/harbor-scanner-grype:latest --load .
# A grype-db.tar.zst next to this file is imported instead of downloading the vulnerability DB.

ARG GRYPE_VERSION=0.119.0
ARG SYFT_VERSION=1.52.0

# grype and syft are built from their release tags with the same Go as the adapter: the release
# binaries lag behind Go security fixes, and they parse untrusted image content. TOOL_DEP_UPDATES
# lists patch-level dependency updates for advisories reported against the released versions.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS tools
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG GRYPE_VERSION
ARG SYFT_VERSION
ARG TOOL_DEP_UPDATES="github.com/containerd/containerd/v2@v2.3.6 go.opentelemetry.io/otel/sdk@v1.45.0"
RUN apk add --no-cache git
WORKDIR /tools
RUN set -eu; \
    for tool in "grype:${GRYPE_VERSION}" "syft:${SYFT_VERSION}"; do \
      name="${tool%%:*}"; version="${tool##*:}"; \
      git clone --quiet --depth 1 --branch "v${version}" "https://github.com/anchore/${name}.git" "/tools/${name}"; \
      cd "/tools/${name}"; \
      for dep in ${TOOL_DEP_UPDATES}; do \
        if go list -m "${dep%@*}" >/dev/null 2>&1; then go get "${dep}"; fi; \
      done; \
      CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
        -ldflags "-s -w -X main.version=${version} -X main.gitCommit=$(git rev-parse HEAD) -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        -o "/out/${name}" "./cmd/${name}"; \
    done; \
    go clean -cache -modcache; rm -rf /tools

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
      -o /out/scanner-grype .

FROM alpine:3.24.1
ARG GRYPE_VERSION

RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates curl su-exec tzdata

COPY --from=tools /out/grype /out/syft /usr/local/bin/

RUN adduser -u 10000 -D -g '' scanner

COPY --from=build /out/scanner-grype /home/scanner/bin/scanner-grype
COPY grype-config.yaml /home/scanner/.grype.yaml
COPY risk-config.yaml /app/risk-config.yaml
COPY --chmod=755 start.sh update-grype-db.sh update-exploitdb.sh /usr/local/bin/

RUN mkdir -p /home/scanner/.cache/grype /home/scanner/.cache/reports /home/scanner/.cache/exploitdb \
      /usr/local/share/exploitdb && \
    chown -R scanner:scanner /home/scanner && \
    install -o scanner -g scanner -m 644 /dev/null /var/log/grype-update.log

# Exploit-DB list baked into the image; start.sh copies it to the volume on the first start.
RUN curl -fsSL --retry 5 --retry-delay 3 -o /usr/local/share/exploitdb/files_exploits.csv \
      https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv && \
    head -n 1 /usr/local/share/exploitdb/files_exploits.csv | grep -q '^id,.*codes'

WORKDIR /home/scanner
ENV PATH=/home/scanner/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    GRYPE_VERSION=${GRYPE_VERSION} \
    GRYPE_DB_CACHE_DIR=/home/scanner/.cache/grype \
    SCANNER_LOG_LEVEL=info

USER scanner
RUN --mount=type=bind,target=/ctx \
    if [ -f /ctx/grype-db.tar.zst ]; then grype db import /ctx/grype-db.tar.zst; else grype db update; fi
USER root

ENV GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    SYFT_CHECK_FOR_APP_UPDATE=false

EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/start.sh"]
