# VPN-TLS

Свой VPN, который снаружи выглядит как обычный HTTPS-сайт.

- Внутри: рукопожатие Noise IK (X25519 + AES-256-GCM), доступ только по ключам клиентов.
- Снаружи: Caddy, TLS 1.3, ClientHello клиента как у Chrome (uTLS), туннель идёт
  через WebSocket Upgrade на секретном пути. Остальные видят страницу-заглушку.
- Несколько клиентов одновременно, у каждого свой адрес; клиенты не видят друг друга.
- Адрес, DNS и MTU клиент получает от сервера; keepalive и автоматическое переподключение.
- Клиент, удалённый из списка, отключается сразу.
- Защита от повтора рукопожатия (метка времени ±5 мин, последние метки хранятся на диске)
  и ограничение попыток подключения с одного IP (10 в минуту).

## Сервер (Docker)

```bash
git clone https://github.com/extree-dev/VPN-TLS.git && cd VPN-TLS
cp .env.example .env          # поменяйте PORT, DOMAIN, VPN_PATH
docker compose up -d --build
```

## Клиенты

```bash
docker compose exec vpn vpn-server client add phone     # строка подключения + QR
docker compose exec vpn vpn-server client list
docker compose exec vpn vpn-server client remove phone  # отключится в течение ~5 с
docker compose exec vpn vpn-server status               # кто онлайн и сколько трафика
```

Если клиент не подключается, а в `docker compose logs vpn` видно
«время клиента отличается от сервера» — включите синхронизацию времени на устройстве.

Строка `vpntls://…` содержит ключ клиента — передавайте её как пароль.

## Клиент для Linux / WSL (консольный)

```bash
go build -o client ./cmd/client
sudo ./client -connect 'vpntls://…' -route-all -dns
```

- `-route-all` — весь IPv4-трафик через туннель, IPv6 блокируется (чтобы не было утечки).
- `-dns` — DNS сервера в `/etc/resolv.conf`; при выходе прежний файл возвращается.
- Ctrl+C — отключиться, маршруты и DNS вернутся.
