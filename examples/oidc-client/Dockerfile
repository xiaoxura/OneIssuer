# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc AS builder
ARG GOPROXY=https://proxy.golang.org,direct
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod GOPROXY="${GOPROXY}" go mod download github.com/go-jose/go-jose/v4
COPY examples/oidc-client ./examples/oidc-client
ARG VERSION=v0.1.0-dev.4
ARG COMMIT=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath \
      -ldflags="-s -w" -o /out/oidc-example ./examples/oidc-client

FROM alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS runtime
ARG VERSION=v0.1.0-dev.4
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
