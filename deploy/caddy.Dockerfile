# Caddy с плагином Cloudflare DNS: сертификат Let's Encrypt через DNS-01,
# без портов 80/443 (они могут быть заняты другим сервером на этом IP).
FROM caddy:2-builder AS builder
RUN xcaddy build --with github.com/caddy-dns/cloudflare

FROM caddy:2-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
