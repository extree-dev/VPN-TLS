// Консольный клиент этапа 1.3 (Linux): туннель внутри HTTPS с отпечатком Chrome.
package main

import (
	"flag"
	"log"

	"github.com/extree-dev/vpn-tls/internal/frame"
	"github.com/extree-dev/vpn-tls/internal/keys"
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
		Addr: *server, SNI: *sni, Pin: *pin, Static: priv, ServerPub: spub,
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
	log.Fatal(frame.Pipe(dev, sess))
}
