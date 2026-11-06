// Консольный клиент этапа 1.2 (Linux): шифрованный туннель до сервера (Noise IK).
package main

import (
	"flag"
	"log"
	"net"
	"time"

	"github.com/extree-dev/vpn-tls/internal/frame"
	"github.com/extree-dev/vpn-tls/internal/keys"
	"github.com/extree-dev/vpn-tls/internal/noise"
	"github.com/extree-dev/vpn-tls/internal/tun"
)

func main() {
	server := flag.String("server", "", "адрес сервера, например 1.2.3.4:8443")
	serverPub := flag.String("server-pub", "", "публичный ключ сервера (из лога сервера)")
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

	conn, err := net.DialTimeout("tcp", *server, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	in, msg1, err := noise.NewInitiator(priv, spub, uint64(time.Now().UnixNano()))
	if err != nil {
		log.Fatal(err)
	}
	if err := frame.Write(conn, msg1); err != nil {
		log.Fatal(err)
	}
	msg2, err := frame.Read(conn, make([]byte, noise.Msg2Size))
	if err != nil {
		log.Fatalf("сервер отклонил подключение (неверный ключ или ключ клиента не добавлен в -allow): %v", err)
	}
	k, err := in.Finish(msg2)
	if err != nil {
		log.Fatal(err)
	}
	conn.SetDeadline(time.Time{})
	sess, err := noise.NewSession(k, conn, frame.Write, frame.Read)
	if err != nil {
		log.Fatal(err)
	}

	dev, err := tun.Open("vpn0")
	if err != nil {
		log.Fatal(err)
	}
	if err := dev.Up(*addr, *mtu); err != nil {
		log.Fatal(err)
	}
	log.Printf("подключён к %s, канал зашифрован, туннель %s", *server, *addr)
	log.Fatal(frame.Pipe(dev, sess))
}
