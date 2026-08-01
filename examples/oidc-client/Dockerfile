# syntax=docker/dockerfile:1.7
ARG GO_VERSION=1.26.5
ARG ALPINE_VERSION=3.23.3

FROM golang:${GO_VERSION}-alpine3.23 AS builder
ARG GOPROXY=https://proxy.golang.org,direct
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod GOPROXY="${GOPROXY}" go mod download github.com/go-jose/go-jose/v4
COPY examples/oidc-client ./examples/oidc-client
ARG VERSION=v0.1.0-dev.3
ARG COMMIT=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath \
      -ldflags="-s -w" -o /out/oidc-example ./examples/oidc-client

FROM alpine:${ALPINE_VERSION} AS runtime
RUN apk upgrade --no-cache
ARG VERSION=v0.1.0-dev.3
ARG COMMIT=unknown
LABEL org.opencontainers.image.title="OneIssuer OIDC interoperability example" \
      org.opencontainers.image.description="Non-production Authorization Code, S256, ID Token, and UserInfo example RP" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.source="https://github.com/oneissuer/oneissuer" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/oidc-example /usr/local/bin/oidc-example
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/oidc-example"]
