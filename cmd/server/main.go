// Сервер этапа 1.3: туннель внутри HTTPS на 443. Посторонние видят обычный сайт.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/extree-dev/vpn-tls/internal/frame"
	"github.com/extree-dev/vpn-tls/internal/keys"
	"github.com/extree-dev/vpn-tls/internal/noise"
	"github.com/extree-dev/vpn-tls/internal/transport"
	"github.com/extree-dev/vpn-tls/internal/tun"
)

func main() {
	listen := flag.String("listen", ":443", "адрес для входящих подключений")
	addr := flag.String("addr", "10.8.0.1/24", "адрес TUN на сервере")
	mtu := flag.Int("mtu", 1400, "MTU туннеля")
	keyFile := flag.String("key", "server.key", "файл приватного ключа сервера (создаётся при первом запуске)")
	allow := flag.String("allow", "", "публичные ключи клиентов через запятую")
	certFile := flag.String("cert", "tls.crt", "TLS-сертификат (если файла нет — создаётся самоподписанный)")
	certKey := flag.String("cert-key", "tls.key", "приватный ключ TLS-сертификата")
	domain := flag.String("domain", "localhost", "домен для самоподписанного сертификата")
	fallback := flag.String("fallback", "", "URL сайта, который видят посторонние (по умолчанию — встроенная заглушка)")
	flag.Parse()

	priv, created, err := keys.LoadOrCreate(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Printf("создан новый ключ сервера: %s", *keyFile)
	}
	log.Printf("публичный ключ сервера: %s", keys.PublicString(priv))

	cert, fp, created, err := transport.LoadOrCreateCert(*certFile, *certKey, *domain)
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Printf("создан самоподписанный сертификат для %s: %s", *domain, *certFile)
	}
	log.Printf("отпечаток сертификата (для -pin клиента): %s", fp)

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

	var site http.Handler = transport.StubSite
	if *fallback != "" {
		u, err := url.Parse(*fallback)
		if err != nil {
			log.Fatal(err)
		}
		rp := httputil.NewSingleHostReverseProxy(u)
		base := rp.Director
		rp.Director = func(r *http.Request) { base(r); r.Host = u.Host }
		rp.ErrorLog = transport.QuietLog
		site = rp
	}

	dev, err := tun.Open("vpn0")
	if err != nil {
		log.Fatal(err)
	}
	if err := dev.Up(*addr, *mtu); err != nil {
		log.Fatal(err)
	}
	log.Printf("TUN %s поднят, адрес %s", dev.Name, *addr)

	sessions := &single{}
	h := &transport.Handler{
		Priv:     priv,
		Allowed:  allowed,
		Fallback: site,
		OnSession: func(sess *noise.Session, conn net.Conn, client string) {
			sessions.run(conn, func() error {
				log.Printf("клиент подключён: %s (%s…)", conn.RemoteAddr(), client[:8])
				return frame.Pipe(dev, sess)
			})
		},
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          transport.QuietLog,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
		},
		// HTTP/2 выключен: туннелю нужен «сырой» поток после ответа.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	log.Printf("слушаю %s (HTTPS), разрешено клиентов: %d", *listen, len(allowed))
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// single держит одну активную сессию: новое подключение вытесняет старое.
// (Несколько одновременных клиентов с разными адресами — на следующих этапах.)
type single struct {
	mu   sync.Mutex
	conn net.Conn
	done chan struct{}
}

func (s *single) run(conn net.Conn, pipe func() error) {
	s.mu.Lock()
	if s.conn != nil {
		s.conn.Close()
		<-s.done
	}
	done := make(chan struct{})
	s.conn, s.done = conn, done
	s.mu.Unlock()

	err := pipe()
	log.Printf("клиент отключён: %v", err)

	s.mu.Lock()
	if s.conn == conn {
		s.conn = nil
	}
	s.mu.Unlock()
	close(done)
}
