// Консольный клиент (Linux): туннель внутри HTTPS с отпечатком Chrome.
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/extree-dev/vpn-tls/internal/frame"
	"github.com/extree-dev/vpn-tls/internal/keys"
	"github.com/extree-dev/vpn-tls/internal/route"
	"github.com/extree-dev/vpn-tls/internal/transport"
	"github.com/extree-dev/vpn-tls/internal/tun"
)

func main() {
	server := flag.String("server", "", "адрес сервера, например 1.2.3.4:443")
	serverPub := flag.String("server-pub", "", "публичный ключ сервера (из лога сервера)")
	sni := flag.String("sni", "", "домен в TLS (SNI); по умолчанию — хост из -server")
	pin := flag.String("pin", "", "отпечаток сертификата сервера (для самоподписанного)")
	keyFile := flag.String("key", "client.key", "файл приватного ключа клиента (создаётся при первом запуске)")
	addr := flag.String("addr", "10.8.0.2/24", "адрес TUN на клиенте")
	mtu := flag.Int("mtu", 1400, "MTU туннеля")
	path := flag.String("path", "/", "секретный путь туннеля на сервере")
	routeAll := flag.Bool("route-all", false, "пустить весь трафик через туннель")
	flag.Parse()

	priv, created, err := keys.LoadOrCreate(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Printf("создан новый ключ клиента: %s", *keyFile)
	}
	log.Printf("публичный ключ клиента: %s", keys.PublicString(priv))
	if *server == "" || *serverPub == "" {
		log.Fatal("укажите -server и -server-pub")
	}
	spub, err := keys.ParsePublic(*serverPub)
	if err != nil {
		log.Fatal(err)
	}

	sess, conn, err := transport.Dial(transport.DialConfig{
		Addr: *server, SNI: *sni, Pin: *pin, Path: *path, Static: priv, ServerPub: spub,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	dev, err := tun.Open("vpn0")
	if err != nil {
		log.Fatal(err)
	}
	if err := dev.Up(*addr, *mtu); err != nil {
		log.Fatal(err)
	}
	log.Printf("подключён к %s по HTTPS, канал зашифрован, туннель %s", *server, *addr)

	undo := func() {}
	if *routeAll {
		ip := conn.RemoteAddr().(*net.TCPAddr).IP
		if undo, err = route.RouteAll(dev.Name, ip); err != nil {
			log.Fatal(err)
		}
		log.Print("весь трафик идёт через туннель (Ctrl+C — отключиться)")
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		undo()
		log.Print("отключено")
		os.Exit(0)
	}()
	err = frame.Pipe(dev, sess)
	undo()
	log.Fatal(err)
}
