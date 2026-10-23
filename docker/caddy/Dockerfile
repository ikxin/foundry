# syntax=docker/dockerfile:1

ARG CADDY_VERSION=2.11.7

FROM caddy:${CADDY_VERSION}-builder AS builder

WORKDIR /build
COPY go.mod go.sum ./
COPY rules.go ./

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    xcaddy build "${CADDY_VERSION}" \
        --with github.com/ikxin/foundry/docker/caddy=.

FROM caddy:${CADDY_VERSION}-alpine

LABEL org.opencontainers.image.title="ikxin/caddy" \
      org.opencontainers.image.description="Caddy static server with local header and redirect rules" \
      org.opencontainers.image.source="https://github.com/ikxin/foundry" \
      org.opencontainers.image.documentation="https://github.com/ikxin/foundry/tree/main/docker/caddy" \
      org.opencontainers.image.vendor="ikxin"

WORKDIR /usr/share/caddy

COPY --from=builder /build/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile

EXPOSE 8080

ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
