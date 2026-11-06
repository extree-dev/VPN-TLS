// Консольный клиент (Linux): туннель внутри HTTPS с отпечатком Chrome.
//
//	sudo ./client -connect 'vpntls://…' -route-all
//
// Адрес в туннеле, DNS и MTU выдаёт сервер. При обрыве клиент переподключается сам.
package main

import (
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/extree-dev/vpn-tls/internal/config"
	"github.com/extree-dev/vpn-tls/internal/keys"
	"github.com/extree-dev/vpn-tls/internal/route"
	"github.com/extree-dev/vpn-tls/internal/transport"
	"github.com/extree-dev/vpn-tls/internal/tun"
	"github.com/extree-dev/vpn-tls/internal/tunnel"
)

func main() {
	connect := flag.String("connect", "", "строка подключения vpntls://… (из vpn-server client add)")
	server := flag.String("server", "", "адрес сервера host:port (если нет -connect)")
	serverPub := flag.String("server-pub", "", "публичный ключ сервера (если нет -connect)")
	sni := flag.String("sni", "", "домен в TLS (SNI); по умолчанию — хост из адреса")
	pin := flag.String("pin", "", "отпечаток сертификата сервера (для самоподписанного)")
	path := flag.String("path", "/", "секретный путь туннеля на сервере")
	keyFile := flag.String("key", "client.key", "файл ключа клиента (если нет -connect)")
	routeAll := flag.Bool("route-all", false, "пустить весь трафик через туннель (IPv6 блокируется)")
	setDNS := flag.Bool("dns", false, "использовать DNS сервера (перезаписывает /etc/resolv.conf, при выходе вернёт)")
	flag.Parse()

	cfg, name := dialConfig(*connect, *server, *serverPub, *sni, *pin, *path, *keyFile)

	// Адрес сервера определяем один раз: после -route-all DNS может идти уже через туннель.
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.SNI == "" && net.ParseIP(host) == nil {
		cfg.SNI = host
	}
	ip, err := resolve4(host)
	if err != nil {
		log.Fatal(err)
	}
	cfg.Addr = net.JoinHostPort(ip.String(), port)
	if cfg.SNI == "" {
		cfg.SNI = host
	}
	if name != "" {
		log.Printf("профиль %q, сервер %s (%s)", name, host, ip)
	}

	var (
		dev      *tun.Device
		out      = make(chan []byte, 512)
		undo     []func()
		addr     string
		attempts int
	)
	cleanup := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cleanup()
		log.Print("отключено")
		os.Exit(0)
	}()

	for {
		sess, conn, payload, err := transport.Dial(cfg)
		if err == nil {
			var c *config.Client
			if c, err = config.ParseClient(payload); err == nil {
				attempts = 0
				if dev == nil {
					if dev, err = tun.Open("vpn0"); err != nil {
						cleanup()
						log.Fatal(err)
					}
					go func() { tunnel.ReadTUN(dev, out) }()
				}
				if c.Addr != addr {
					if err := dev.Up(c.Addr, c.MTU); err != nil {
						cleanup()
						log.Fatal(err)
					}
					addr = c.Addr
				}
				if len(undo) == 0 {
					undo = setup(dev.Name, ip, c, *routeAll, *setDNS)
				}
				log.Printf("подключён: адрес %s, DNS %s, канал зашифрован", c.Addr, strings.Join(c.DNS, " "))
				err = tunnel.Link(sess, conn, out, func(p []byte) error {
					_, err := dev.Write(p)
					return err
				}, time.Duration(c.Keepalive)*time.Second)
				log.Printf("соединение потеряно: %v", err)
			} else {
				conn.Close()
			}
		}
		if err != nil && isFatal(err) {
			cleanup()
			log.Fatal(err)
		}
		attempts++
		wait := min(time.Duration(1<<min(attempts, 5))*time.Second, 30*time.Second)
		if err != nil {
			log.Printf("ошибка: %v; повтор через %s", err, wait)
		}
		time.Sleep(wait)
	}
}

// setup включает маршруты и DNS после первого подключения. Пока клиент
// переподключается, маршруты остаются: трафик не уходит мимо туннеля.
func setup(dev string, server net.IP, c *config.Client, routeAll, setDNS bool) []func() {
	var undo []func()
	if routeAll {
		u, err := route.RouteAll(dev, server)
		if err != nil {
			log.Fatal(err)
		}
		undo = append(undo, u)
		log.Print("весь трафик идёт через туннель, IPv6 заблокирован (Ctrl+C — отключиться)")
	}
	if setDNS {
		u, err := route.SetDNS(c.DNS)
		if err != nil {
			log.Printf("DNS не настроен: %v", err)
		} else {
			undo = append(undo, u)
		}
	}
	return undo
}

// isFatal — ошибки, которые повтор не исправит.
func isFatal(err error) bool {
	s := err.Error()
	return strings.Contains(s, "отпечаток сертификата") || strings.Contains(s, "отклонил")
}

func dialConfig(connect, server, serverPub, sni, pin, path, keyFile string) (transport.DialConfig, string) {
	if connect != "" {
		l, err := config.ParseLink(connect)
		if err != nil {
			log.Fatal(err)
		}
		return transport.DialConfig{Addr: l.Addr, SNI: l.SNI, Pin: l.Pin, Path: l.Path,
			Static: l.ClientKey, ServerPub: l.ServerPub}, l.Name
	}
	priv, created, err := keys.LoadOrCreate(keyFile)
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Printf("создан новый ключ клиента: %s", keyFile)
	}
	log.Printf("публичный ключ клиента: %s", keys.PublicString(priv))
	if server == "" || serverPub == "" {
		log.Fatal("укажите -connect 'vpntls://…' или -server и -server-pub")
	}
	spub, err := keys.ParsePublic(serverPub)
	if err != nil {
		log.Fatal(err)
	}
	return transport.DialConfig{Addr: server, SNI: sni, Pin: pin, Path: path,
		Static: priv, ServerPub: spub}, ""
}

func resolve4(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
		return nil, errors.New("нужен IPv4-адрес сервера")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, errors.New(host + ": нет IPv4-адреса")
}
