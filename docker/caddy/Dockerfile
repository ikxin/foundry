ARG CADDY_VERSION=2.11.7

FROM caddy:${CADDY_VERSION}-builder AS builder

WORKDIR /build
COPY go.mod go.sum ./
COPY rules.go ./

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    xcaddy build "${CADDY_VERSION}" \
        --with github.com/ikxin/foundry/docker/caddy=.

FROM alpine:3.23

RUN apk add --no-cache ca-certificates mailcap

ENV XDG_CONFIG_HOME=/config \
    XDG_DATA_HOME=/data

WORKDIR /usr/share/caddy

COPY --from=builder /build/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile

EXPOSE 8080

ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
