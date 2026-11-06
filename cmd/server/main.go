// Сервер этапа 1.1: принимает одного клиента по TCP и соединяет его с TUN.
// Без шифрования — только для проверки, что туннель работает. Не выставлять в интернет надолго.
package main

import (
	"flag"
	"log"
	"net"

	"github.com/extree-dev/vpn-tls/internal/frame"
	"github.com/extree-dev/vpn-tls/internal/tun"
)

func main() {
	listen := flag.String("listen", ":8443", "адрес для входящих подключений")
	addr := flag.String("addr", "10.8.0.1/24", "адрес TUN на сервере")
	mtu := flag.Int("mtu", 1400, "MTU туннеля")
	flag.Parse()

	dev, err := tun.Open("vpn0")
	if err != nil {
		log.Fatal(err)
	}
	if err := dev.Up(*addr, *mtu); err != nil {
		log.Fatal(err)
	}
	log.Printf("TUN %s поднят, адрес %s", dev.Name, *addr)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("слушаю %s", *listen)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		log.Printf("клиент подключён: %s", conn.RemoteAddr())
		err = frame.Pipe(dev, conn) // пока один клиент за раз
		conn.Close()
		log.Printf("клиент отключён: %v", err)
	}
}
