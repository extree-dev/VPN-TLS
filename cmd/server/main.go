// Сервер VPN: туннель внутри HTTPS. Посторонние видят обычный сайт.
//
// Режимы:
//   - напрямую: сам слушает TLS на -listen (по умолчанию :443);
//   - за обратным прокси (Caddy): -plain :8080, TLS и сайт обслуживает прокси.
//
// Управление клиентами:
//
//	vpn-server client add <имя>     — создать клиента, показать строку подключения и QR
//	vpn-server client list          — список клиентов
//	vpn-server client remove <имя>  — удалить клиента (его сессия сразу закроется)
//
// Любой флаг можно задать переменной окружения VPN_<ИМЯ>, например VPN_PATH.
package main

import (
	"crypto/ecdh"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/extree-dev/vpn-tls/internal/clients"
	"github.com/extree-dev/vpn-tls/internal/config"
	"github.com/extree-dev/vpn-tls/internal/keys"
	"github.com/extree-dev/vpn-tls/internal/noise"
	"github.com/extree-dev/vpn-tls/internal/route"
	"github.com/extree-dev/vpn-tls/internal/transport"
	"github.com/extree-dev/vpn-tls/internal/tun"
	"github.com/extree-dev/vpn-tls/internal/tunnel"
)

type options struct {
	listen, plain, path, addr, keyFile, allow, clientsFile string
	certFile, certKey, domain, fallback, dns, public, pin  string
	mtu                                                    int
	keepalive                                              time.Duration
	nat, isolate                                           bool
}

func main() {
	log.SetFlags(log.LstdFlags)
	o := &options{}
	fs := flag.NewFlagSet("vpn-server", flag.ExitOnError)
	str := func(p *string, name, def, usage string) { fs.StringVar(p, name, env(name, def), usage) }
	str(&o.listen, "listen", ":443", "адрес TLS (режим без прокси)")
	str(&o.plain, "plain", "", "слушать обычный HTTP на этом адресе (режим за обратным прокси), например :8080")
	str(&o.path, "path", "", "секретный путь туннеля, например /api/stream (пусто — любой путь)")
	str(&o.addr, "addr", "10.8.0.1/24", "адрес сервера в туннеле и подсеть клиентов")
	str(&o.keyFile, "key", "server.key", "файл приватного ключа сервера (создаётся при первом запуске)")
	str(&o.allow, "allow", "", "дополнительные публичные ключи клиентов через запятую")
	str(&o.clientsFile, "clients", "clients.txt", "файл клиентов (перечитывается при изменении)")
	str(&o.certFile, "cert", "tls.crt", "TLS-сертификат (если файла нет — создаётся самоподписанный)")
	str(&o.certKey, "cert-key", "tls.key", "приватный ключ TLS-сертификата")
	str(&o.domain, "domain", "localhost", "домен сервера (SNI и имя в сертификате)")
	str(&o.fallback, "fallback", "", "URL сайта, который видят посторонние (режим без прокси)")
	str(&o.dns, "dns", "1.1.1.1,1.0.0.1", "DNS-серверы для клиентов через запятую")
	str(&o.public, "public", "", "внешний адрес host:port для строк подключения (по умолчанию <domain>:$VPN_PUBLIC_PORT или :443)")
	str(&o.pin, "pin", "auto", "отпечаток в строках подключения: auto — из -cert, off — без pin (настоящий сертификат)")
	fs.IntVar(&o.mtu, "mtu", envInt("mtu", 1400), "MTU туннеля")
	fs.DurationVar(&o.keepalive, "keepalive", envDur("keepalive", 15*time.Second), "интервал keepalive")
	fs.BoolVar(&o.nat, "nat", envBool("nat", false), "выпускать клиентов в интернет (MASQUERADE)")
	fs.BoolVar(&o.isolate, "isolate", envBool("isolate", true), "запретить клиентам видеть друг друга")

	fs.Parse(os.Args[1:])
	if rest := fs.Args(); len(rest) > 0 {
		if rest[0] != "client" {
			log.Fatalf("неизвестная команда %q", rest[0])
		}
		clientCmd(o, rest[1:])
		return
	}
	serve(o)
}

func serve(o *options) {
	priv := loadKey(o.keyFile)
	log.Printf("публичный ключ сервера: %s", keys.PublicString(priv))

	cert, fp, created, err := transport.LoadOrCreateCert(o.certFile, o.certKey, o.domain)
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Printf("создан самоподписанный сертификат для %s: %s", o.domain, o.certFile)
	}
	log.Printf("отпечаток сертификата: %s", fp)

	gwPrefix, err := netip.ParsePrefix(o.addr)
	if err != nil || !gwPrefix.Addr().Is4() {
		log.Fatalf("-addr %q: нужен IPv4 с маской, например 10.8.0.1/24", o.addr)
	}
	var dns []string
	for _, d := range strings.Split(o.dns, ",") {
		if d = strings.TrimSpace(d); d != "" {
			dns = append(dns, d)
		}
	}

	store := &clients.Store{File: o.clientsFile, Extra: o.allow}
	if n := len(store.Entries()); n == 0 {
		log.Printf("клиентов пока нет — добавьте: vpn-server client add <имя>")
	} else {
		log.Printf("клиентов в списке: %d", n)
	}

	dev, err := tun.Open("vpn0")
	if err != nil {
		log.Fatal(err)
	}
	if err := dev.Up(o.addr, o.mtu); err != nil {
		log.Fatal(err)
	}
	log.Printf("TUN %s поднят, адрес %s", dev.Name, o.addr)

	undoNAT := func() {}
	if o.nat {
		if undoNAT, err = route.EnableNAT(gwPrefix.Masked().String()); err != nil {
			log.Fatal(err)
		}
		log.Printf("NAT включён для %s", gwPrefix.Masked())
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		undoNAT()
		log.Print("выход")
		os.Exit(0)
	}()

	router := tunnel.NewRouter(dev, gwPrefix, o.isolate)
	go func() { log.Fatal(router.Run()) }()

	// Удалённый из списка клиент отключается сразу, а не при следующем подключении.
	kick := func() {
		router.Kick(func(key string) bool {
			pub, err := keys.ParsePublic(key)
			if err != nil {
				return false
			}
			_, ok := store.Lookup(pub.Bytes())
			return ok
		})
	}
	store.OnChange(kick)
	go func() {
		for range time.Tick(5 * time.Second) {
			store.Refresh()
		}
	}()

	reserved := func() map[netip.Addr]bool {
		m := map[netip.Addr]bool{}
		for _, e := range store.Entries() {
			if e.IP.IsValid() {
				m[e.IP] = true
			}
		}
		return m
	}
	lease := func(pub *ecdh.PublicKey) (clients.Entry, netip.Addr, error) {
		e, ok := store.Lookup(pub.Bytes())
		if !ok {
			return e, netip.Addr{}, fmt.Errorf("неизвестный клиент")
		}
		ip, err := router.Lease(e.Key, e.IP, reserved())
		return e, ip, err
	}

	h := &transport.Handler{
		Priv:     priv,
		Path:     o.path,
		Fallback: transport.StubSite,
		Allowed: func(pub []byte) bool {
			_, ok := store.Lookup(pub)
			return ok
		},
		Payload: func(pub *ecdh.PublicKey) ([]byte, error) {
			_, ip, err := lease(pub)
			if err != nil {
				log.Printf("клиент %s…: %v", keys.EncodePublic(pub)[:8], err)
				return nil, err
			}
			cfg := &config.Client{
				Addr:      netip.PrefixFrom(ip, gwPrefix.Bits()).String(),
				Gateway:   router.Gateway().String(),
				DNS:       dns,
				MTU:       o.mtu,
				Keepalive: int(o.keepalive / time.Second),
			}
			return cfg.Marshal(), nil
		},
		OnSession: func(sess *noise.Session, conn net.Conn, pub *ecdh.PublicKey) {
			e, ip, err := lease(pub)
			if err != nil {
				return
			}
			name := e.Name
			if name == "" {
				name = e.Key[:8] + "…"
			}
			log.Printf("подключён %s (%s), адрес %s; всего онлайн: %d", name, remote(conn), ip, router.Count()+1)
			err = router.Serve(e.Key, ip, sess, conn, o.keepalive)
			log.Printf("отключён %s (%s): %v", name, ip, err)
		},
	}
	if o.fallback != "" {
		u, err := url.Parse(o.fallback)
		if err != nil {
			log.Fatal(err)
		}
		rp := httputil.NewSingleHostReverseProxy(u)
		base := rp.Director
		rp.Director = func(r *http.Request) { base(r); r.Host = u.Host }
		rp.ErrorLog = transport.QuietLog
		h.Fallback = rp
	}

	if o.plain != "" {
		srv := &http.Server{Addr: o.plain, Handler: h, ReadHeaderTimeout: 10 * time.Second, ErrorLog: transport.QuietLog}
		log.Printf("слушаю %s (HTTP за обратным прокси), путь %q", o.plain, o.path)
		log.Fatal(srv.ListenAndServe())
	}
	srv := &http.Server{
		Addr: o.listen, Handler: h,
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, ErrorLog: transport.QuietLog,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		// HTTP/2 выключен: туннелю нужен «сырой» поток после ответа.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	log.Printf("слушаю %s (HTTPS), путь %q", o.listen, o.path)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// remote — адрес соединения (за прокси это адрес прокси).
func remote(c net.Conn) string { return c.RemoteAddr().String() }

func loadKey(path string) *ecdh.PrivateKey {
	priv, created, err := keys.LoadOrCreate(path)
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Printf("создан новый ключ сервера: %s", path)
	}
	return priv
}

func env(name, def string) string {
	if v, ok := os.LookupEnv("VPN_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))); ok {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	var v int
	if _, err := fmt.Sscan(env(name, ""), &v); err == nil {
		return v
	}
	return def
}

func envBool(name string, def bool) bool {
	switch strings.ToLower(env(name, "")) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func envDur(name string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(env(name, "")); err == nil {
		return d
	}
	return def
}
