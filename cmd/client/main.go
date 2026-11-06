// Консольный клиент этапа 1.1 (Linux): подключается к серверу и соединяет его с локальным TUN.
package main

import (
	"flag"
	"log"
	"net"

	"github.com/extree-dev/vpn-tls/internal/frame"
	"github.com/extree-dev/vpn-tls/internal/tun"
)

func main() {
	server := flag.String("server", "", "адрес сервера, например 1.2.3.4:8443")
	addr := flag.String("addr", "10.8.0.2/24", "адрес TUN на клиенте")
	mtu := flag.Int("mtu", 1400, "MTU туннеля")
	flag.Parse()
	if *server == "" {
		log.Fatal("укажите -server")
	}

	dev, err := tun.Open("vpn0")
	if err != nil {
		log.Fatal(err)
	}
	if err := dev.Up(*addr, *mtu); err != nil {
		log.Fatal(err)
	}

	conn, err := net.Dial("tcp", *server)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("подключён к %s, туннель %s", *server, *addr)
	log.Fatal(frame.Pipe(dev, conn))
}
