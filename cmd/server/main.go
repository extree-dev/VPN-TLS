// Сервер VPN: туннель внутри HTTPS. Посторонние видят обычный сайт.
//
// Два режима:
//   - напрямую: сам слушает TLS на -listen (по умолчанию :443);
//   - за обратным прокси (Caddy): -plain :8080, TLS и сайт обслуживает прокси.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/extree-dev/vpn-tls/internal/frame"
	"github.com/extree-dev/vpn-tls/internal/keys"
	"github.com/extree-dev/vpn-tls/internal/noise"
	"github.com/extree-dev/vpn-tls/internal/route"
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
	plain := flag.String("plain", "", "слушать обычный HTTP на этом адресе (режим за обратным прокси), например :8080")
	path := flag.String("path", "", "секретный путь туннеля, например /api/stream (пусто — любой путь)")
	allowFile := flag.String("allow-file", "", "файл с публичными ключами клиентов, по одному в строке")
	nat := flag.Bool("nat", false, "выпускать клиентов в интернет (MASQUERADE через интерфейс по умолчанию)")
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

	allowed := &allowList{flag: *allow, file: *allowFile}
	if n := allowed.count(); n == 0 {
		log.Printf("ВНИМАНИЕ: не задан ни один клиент — добавьте ключ в -allow или в %s", orDash(*allowFile))
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

	if *nat {
		_, subnet, err := net.ParseCIDR(*addr)
		if err != nil {
			log.Fatal(err)
		}
		undo, err := route.EnableNAT(subnet.String())
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("NAT включён для %s: клиенты выходят в интернет через сервер", subnet)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sig
			undo()
			log.Print("NAT снят, выход")
			os.Exit(0)
		}()
	}

	sessions := &single{}
	h := &transport.Handler{
		Priv:     priv,
		Allowed:  allowed.has,
		Fallback: site,
		Path:     *path,
		OnSession: func(sess *noise.Session, conn net.Conn, client string) {
			sessions.run(conn, func() error {
				log.Printf("клиент подключён: %s (%s…)", conn.RemoteAddr(), client[:8])
				return frame.Pipe(dev, sess)
			})
		},
	}
	if *plain != "" {
		srv := &http.Server{
			Addr:              *plain,
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			ErrorLog:          transport.QuietLog,
		}
		log.Printf("слушаю %s (HTTP за обратным прокси), путь %q, разрешено клиентов: %d", *plain, *path, allowed.count())
		log.Fatal(srv.ListenAndServe())
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
	log.Printf("слушаю %s (HTTPS), разрешено клиентов: %d", *listen, allowed.count())
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

// allowList — разрешённые ключи из флага и файла. Файл перечитывается при
// изменении, поэтому клиентов можно добавлять без перезапуска сервера.
type allowList struct {
	flag, file string

	mu    sync.Mutex
	mtime time.Time
	keys  map[string]bool
}

func (a *allowList) has(pub []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reload()
	return a.keys[string(pub)]
}

func (a *allowList) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reload()
	return len(a.keys)
}

func (a *allowList) reload() {
	var mtime time.Time
	var data []byte
	if a.file != "" {
		if st, err := os.Stat(a.file); err == nil {
			mtime = st.ModTime()
		}
	}
	if a.keys != nil && mtime.Equal(a.mtime) {
		return
	}
	if a.file != "" {
		var err error
		if data, err = os.ReadFile(a.file); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("%s: %v", a.file, err)
		}
	}
	keys := map[string]bool{}
	lines := append(strings.Split(a.flag, ","), strings.Split(string(data), "\n")...)
	for _, line := range lines {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i] // комментарий
		}
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		pub, err := keys2pub(line)
		if err != nil {
			log.Printf("пропускаю неверный ключ клиента %q: %v", line, err)
			continue
		}
		keys[string(pub)] = true
	}
	if a.keys != nil {
		log.Printf("список клиентов обновлён: %d", len(keys))
	}
	a.keys, a.mtime = keys, mtime
}

func keys2pub(s string) ([]byte, error) {
	p, err := keys.ParsePublic(s)
	if err != nil {
		return nil, err
	}
	return p.Bytes(), nil
}

func orDash(s string) string {
	if s == "" {
		return "-allow-file"
	}
	return s
}
