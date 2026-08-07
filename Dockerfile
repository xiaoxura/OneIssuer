# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc AS builder
ARG GOPROXY=https://proxy.golang.org,direct
WORKDIR /src

COPY go.mod go.sum ./
# Download only runtime roots here. Testcontainers and other test-only modules
# remain outside the final-image build graph; transitive runtime modules are
# fetched into the same cache by the compile step below.
RUN --mount=type=cache,target=/go/pkg/mod GOPROXY="${GOPROXY}" go mod download \
	  github.com/go-jose/go-jose/v4 \
	  github.com/jackc/pgx/v5 \
	  github.com/ory/fosite \
      github.com/pressly/goose/v3 \
      github.com/prometheus/client_golang \
      github.com/prometheus/common

COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations

ARG VERSION=v0.1.0-dev.4
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME}" \
      -o /out/oneissuer ./cmd/oneissuer

FROM alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS runtime

# Base and frontend digests are deliberately immutable. Dependency updates are
# explicit review events rather than mutable package upgrades during a build.

ARG VERSION=v0.1.0-dev.4
ARG COMMIT=unknown
ARG SOURCE_REPOSITORY=https://github.com/oneissuer/oneissuer
LABEL org.opencontainers.image.title="OneIssuer" \
      org.opencontainers.image.description="Single-Issuer self-hosted identity and OIDC Authorization Code provider" \
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
