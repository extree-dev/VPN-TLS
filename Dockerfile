# Сборка
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vpn-server ./cmd/server

# Образ сервера: бинарник + ip/iptables для TUN и NAT
FROM alpine:3.20
RUN apk add --no-cache iproute2 iptables
COPY --from=build /out/vpn-server /usr/local/bin/vpn-server
WORKDIR /data
VOLUME /data
ENTRYPOINT ["vpn-server"]
