# VPN-TLS

Свой VPN, который снаружи выглядит как обычный HTTPS-сайт.

- Внутри: рукопожатие Noise IK (X25519 + AES-256-GCM), доступ только по ключам клиентов.
- Снаружи: Caddy на 443, TLS 1.3, ClientHello клиента как у Chrome (uTLS),
  туннель идёт через WebSocket Upgrade на секретном пути. Остальные видят страницу-заглушку.

## Сервер (Docker)

```bash
git clone https://github.com/extree-dev/VPN-TLS.git && cd VPN-TLS
cp .env.example .env          # поменяйте PORT, DOMAIN, VPN_PATH
docker compose up -d --build
docker compose logs vpn       # публичный ключ сервера и отпечаток сертификата
```

Добавить клиента — дописать его публичный ключ строкой в `data/clients.txt`.
Перезапуск не нужен, сервер перечитывает файл сам.

## Клиент (Linux / WSL, пока консольный)

```bash
go build -o client ./cmd/client
sudo ./client                 # первый запуск: создаст client.key и покажет публичный ключ
sudo ./client -server IP:PORT -sni DOMAIN -path VPN_PATH \
  -server-pub "КЛЮЧ_СЕРВЕРА" -pin "ОТПЕЧАТОК" -route-all
```

`-route-all` пускает весь трафик через туннель. Ctrl+C — отключиться, маршруты вернутся.
