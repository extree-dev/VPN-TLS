// Package mobile — ядро VPN для мобильных приложений (iOS, позже Android).
// Собирается через gomobile bind; наружу торчит только простой API:
//
//	t, err := mobile.Connect(link, writer, listener) // подключиться
//	t.Settings()                                     // адрес, DNS, MTU, IP сервера — JSON
//	t.WritePacket(p)                                 // пакет от системы → в туннель
//	t.Close()                                        // отключиться
//
// Пакеты из туннеля отдаются системе через writer.WritePacket.
package mobile

import (
	"encoding/json"
	"errors"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/extree-dev/vpn-tls/internal/config"
	"github.com/extree-dev/vpn-tls/internal/noise"
	"github.com/extree-dev/vpn-tls/internal/transport"
	"github.com/extree-dev/vpn-tls/internal/tunnel"
)

// PacketWriter отдаёт пакеты из туннеля системе (NEPacketTunnelFlow на iOS).
type PacketWriter interface {
	WritePacket(p []byte)
}

// Listener получает изменения состояния: "connected", "reconnecting", "failed", "closed".
type Listener interface {
	OnStatus(state, detail string)
}

// Tunnel — активное подключение. Сам переподключается при обрывах.
type Tunnel struct {
	cfg      transport.DialConfig
	w        PacketWriter
	l        Listener
	out      chan []byte
	settings string

	mu     sync.Mutex
	conn   net.Conn
	closed bool
	stop   chan struct{}
}

// tunnelSettings — то, что нужно системе для настройки VPN (уходит наружу JSON).
type tunnelSettings struct {
	Addr      string   `json:"ip"`     // 10.8.0.2/24
	DNS       []string `json:"dns"`    // DNS в туннеле
	MTU       int      `json:"mtu"`    //
	Server    string   `json:"server"` // IPv4 сервера (tunnelRemoteAddress)
	Name      string   `json:"name"`   // имя профиля из ссылки
	Keepalive int      `json:"ka"`
}

// Connect разбирает ссылку vpntls://, подключается и возвращает туннель.
// Первое подключение синхронное: настройки нужны системе до старта.
func Connect(link string, w PacketWriter, l Listener) (*Tunnel, error) {
	// У расширения VPN на iOS жёсткий лимит памяти (~50 МБ).
	debug.SetMemoryLimit(32 << 20)

	lk, err := config.ParseLink(link)
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(lk.Addr)
	if err != nil {
		return nil, err
	}
	ip, err := resolve4(host)
	if err != nil {
		return nil, err
	}
	sni := lk.SNI
	if sni == "" {
		sni = host
	}
	t := &Tunnel{
		cfg: transport.DialConfig{Addr: net.JoinHostPort(ip.String(), port), SNI: sni, Pin: lk.Pin,
			Path: lk.Path, Static: lk.ClientKey, ServerPub: lk.ServerPub},
		w: w, l: l, out: make(chan []byte, 512), stop: make(chan struct{}),
	}
	sess, conn, payload, err := transport.Dial(t.cfg)
	if err != nil {
		return nil, err
	}
	c, err := config.ParseClient(payload)
	if err != nil {
		conn.Close()
		return nil, err
	}
	s, _ := json.Marshal(tunnelSettings{Addr: c.Addr, DNS: c.DNS, MTU: c.MTU, Server: ip.String(), Name: lk.Name, Keepalive: c.Keepalive})
	t.settings = string(s)
	t.conn = conn
	go t.run(sess, conn, time.Duration(c.Keepalive)*time.Second)
	return t, nil
}

// Settings — JSON: {"ip","dns","mtu","server","name","ka"}.
func (t *Tunnel) Settings() string { return t.settings }

// WritePacket передаёт пакет от системы в туннель. Срез копируется.
func (t *Tunnel) WritePacket(p []byte) {
	if len(p) == 0 || p[0]>>4 != 4 {
		return // туннель только IPv4; IPv6 отбрасываем, чтобы он не утёк мимо VPN
	}
	select {
	case t.out <- append([]byte(nil), p...):
	default:
	}
}

// Close отключает туннель.
func (t *Tunnel) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	close(t.stop)
	if t.conn != nil {
		t.conn.Close()
	}
}

func (t *Tunnel) status(state, detail string) {
	if t.l != nil {
		t.l.OnStatus(state, detail)
	}
}

func (t *Tunnel) run(sess *noise.Session, conn net.Conn, ka time.Duration) {
	attempts := 0
	for {
		t.status("connected", "")
		err := tunnel.Link(sess, conn, t.out, func(p []byte) error {
			t.w.WritePacket(p)
			return nil
		}, ka)
		for {
			select {
			case <-t.stop:
				t.status("closed", "")
				return
			default:
			}
			attempts++
			detail := "соединение потеряно"
			if err != nil {
				detail = err.Error()
			}
			t.status("reconnecting", detail)
			wait := min(time.Duration(1<<min(attempts, 5))*time.Second, 30*time.Second)
			select {
			case <-t.stop:
				t.status("closed", "")
				return
			case <-time.After(wait):
			}
			var payload []byte
			sess, conn, payload, err = transport.Dial(t.cfg)
			if err != nil {
				if fatal(err) {
					t.status("failed", err.Error())
					return
				}
				continue
			}
			if c, perr := config.ParseClient(payload); perr == nil {
				ka = time.Duration(c.Keepalive) * time.Second
			}
			t.mu.Lock()
			if t.closed {
				t.mu.Unlock()
				conn.Close()
				t.status("closed", "")
				return
			}
			t.conn = conn
			t.mu.Unlock()
			attempts = 0
			break
		}
	}
}

// fatal — ошибки, которые повтор не исправит (ключ отозван, чужой сервер).
func fatal(err error) bool {
	s := err.Error()
	return strings.Contains(s, "отклонил") || strings.Contains(s, "отпечаток сертификата")
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
