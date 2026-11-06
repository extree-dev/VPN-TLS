// Сервер этапа 1.2: шифрованный туннель (Noise IK), доступ только для разрешённых ключей.
package main

import (
	"crypto/ecdh"
	"flag"
	"log"
	"net"
	"strings"
	"time"

	"github.com/extree-dev/vpn-tls/internal/frame"
	"github.com/extree-dev/vpn-tls/internal/keys"
	"github.com/extree-dev/vpn-tls/internal/noise"
	"github.com/extree-dev/vpn-tls/internal/tun"
)

func main() {
	listen := flag.String("listen", ":8443", "адрес для входящих подключений")
	addr := flag.String("addr", "10.8.0.1/24", "адрес TUN на сервере")
	mtu := flag.Int("mtu", 1400, "MTU туннеля")
	keyFile := flag.String("key", "server.key", "файл приватного ключа сервера (создаётся при первом запуске)")
	allow := flag.String("allow", "", "публичные ключи клиентов через запятую")
	flag.Parse()

	priv, created, err := keys.LoadOrCreate(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Printf("создан новый ключ сервера: %s", *keyFile)
	}
	log.Printf("публичный ключ сервера: %s", keys.PublicString(priv))

	allowed := map[string]bool{}
	for _, s := range strings.Split(*allow, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		pub, err := keys.ParsePublic(s)
		if err != nil {
			log.Fatal(err)
		}
		allowed[string(pub.Bytes())] = true
	}
	if len(allowed) == 0 {
		log.Fatal("не задан ни один клиент: укажите -allow <публичный ключ клиента>")
	}

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
	log.Printf("слушаю %s, разрешено клиентов: %d", *listen, len(allowed))

	lastTS := map[string]uint64{} // защита от повтора рукопожатия (сбрасывается при перезапуске)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		sess, client, err := handshake(conn, priv, allowed, lastTS)
		if err != nil {
			log.Printf("%s: отклонён: %v", conn.RemoteAddr(), err)
			conn.Close()
			continue
		}
		log.Printf("клиент подключён: %s (%s…)", conn.RemoteAddr(), client[:8])
		err = frame.Pipe(dev, sess) // пока один клиент за раз
		conn.Close()
		log.Printf("клиент отключён: %v", err)
	}
}

func handshake(conn net.Conn, priv *ecdh.PrivateKey, allowed map[string]bool, lastTS map[string]uint64) (*noise.Session, string, error) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	buf := make([]byte, noise.Msg1Size)
	msg, err := frame.Read(conn, buf)
	if err != nil {
		return nil, "", err
	}
	req, err := noise.ReadRequest(priv, msg)
	if err != nil {
		return nil, "", err
	}
	id := string(req.ClientPub.Bytes())
	if !allowed[id] {
		return nil, "", noise.ErrHandshake
	}
	if req.Timestamp <= lastTS[id] {
		return nil, "", noise.ErrHandshake // повтор старого сообщения
	}
	lastTS[id] = req.Timestamp

	resp, k, err := req.Accept()
	if err != nil {
		return nil, "", err
	}
	if err := frame.Write(conn, resp); err != nil {
		return nil, "", err
	}
	sess, err := noise.NewSession(k, conn, frame.Write, frame.Read)
	return sess, keys.EncodePublic(req.ClientPub), err
}
