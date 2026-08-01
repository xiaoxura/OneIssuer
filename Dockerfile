# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.26.5
ARG ALPINE_VERSION=3.23.3

FROM golang:${GO_VERSION}-alpine3.23 AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /src

COPY go.mod go.sum ./
# Download only runtime roots here. Testcontainers and other test-only modules
# remain outside the final-image build graph; transitive runtime modules are
# fetched into the same cache by the compile step below.
RUN --mount=type=cache,target=/go/pkg/mod go mod download \
      github.com/jackc/pgx/v5 \
      github.com/pressly/goose/v3 \
      github.com/prometheus/client_golang \
      github.com/prometheus/common

COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations

ARG VERSION=v0.1.0-dev.2
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME}" \
      -o /out/oneissuer ./cmd/oneissuer

FROM alpine:${ALPINE_VERSION} AS runtime

# The exact base tag is retained for reviewable builds while security fixes
# published to that stable Alpine branch are applied before the image is
# scanned. The final package set is captured by the resulting image digest.
RUN apk upgrade --no-cache

ARG VERSION=v0.1.0-dev.2
ARG COMMIT=unknown
ARG SOURCE_REPOSITORY=https://github.com/oneissuer/oneissuer
LABEL org.opencontainers.image.title="OneIssuer" \
      org.opencontainers.image.description="Single-issuer self-hosted identity and OIDC client foundation" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.source="${SOURCE_REPOSITORY}" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/oneissuer /usr/local/bin/oneissuer

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/oneissuer"]
CMD ["serve"]
