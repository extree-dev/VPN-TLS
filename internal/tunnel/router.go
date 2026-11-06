package tunnel

import (
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/extree-dev/vpn-tls/internal/noise"
)

// Router — серверная сторона: раздаёт адреса и разводит пакеты из TUN по
// клиентам по адресу назначения.
type Router struct {
	tun     io.ReadWriter
	gw      netip.Addr   // адрес сервера в туннеле
	prefix  netip.Prefix // подсеть туннеля
	isolate bool         // запрещать клиентам видеть друг друга

	mu     sync.Mutex
	peers  map[netip.Addr]*peer
	leases map[string]netip.Addr // ключ клиента → выданный адрес
}

type peer struct {
	key  string
	ip   netip.Addr
	out  chan []byte
	conn net.Conn
}

// NewRouter. addr — адрес сервера с маской, например 10.8.0.1/24.
func NewRouter(tun io.ReadWriter, addr netip.Prefix, isolate bool) *Router {
	return &Router{
		tun: tun, gw: addr.Addr(), prefix: addr.Masked(), isolate: isolate,
		peers: map[netip.Addr]*peer{}, leases: map[string]netip.Addr{},
	}
}

// Prefix — подсеть туннеля.
func (r *Router) Prefix() netip.Prefix { return r.prefix }

// Gateway — адрес сервера в туннеле.
func (r *Router) Gateway() netip.Addr { return r.gw }

// Lease выдаёт клиенту адрес. fixed — закреплённый в clients.txt адрес (или нулевой),
// reserved — все закреплённые адреса, их нельзя выдавать другим.
func (r *Router) Lease(key string, fixed netip.Addr, reserved map[netip.Addr]bool) (netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fixed.IsValid() {
		if !r.usable(fixed) {
			return netip.Addr{}, errors.New("закреплённый адрес " + fixed.String() + " вне подсети туннеля")
		}
		r.leases[key] = fixed
		return fixed, nil
	}
	if ip, ok := r.leases[key]; ok && !reserved[ip] {
		return ip, nil
	}
	used := map[netip.Addr]bool{}
	for k, ip := range r.leases {
		if k != key {
			used[ip] = true
		}
	}
	for ip := r.prefix.Addr().Next(); r.prefix.Contains(ip); ip = ip.Next() {
		if r.usable(ip) && !reserved[ip] && !used[ip] {
			r.leases[key] = ip
			return ip, nil
		}
	}
	return netip.Addr{}, errors.New("в подсети туннеля закончились свободные адреса")
}

func (r *Router) usable(ip netip.Addr) bool {
	return r.prefix.Contains(ip) && ip != r.gw && ip != r.prefix.Addr() && r.prefix.Contains(ip.Next())
}

// Serve обслуживает сессию клиента с адресом ip, пока она жива.
// Прежняя сессия с тем же адресом закрывается.
func (r *Router) Serve(key string, ip netip.Addr, sess *noise.Session, conn net.Conn, keepalive time.Duration) error {
	p := &peer{key: key, ip: ip, out: make(chan []byte, 512), conn: conn}
	r.mu.Lock()
	if old := r.peers[ip]; old != nil {
		old.conn.Close()
	}
	r.peers[ip] = p
	r.mu.Unlock()

	err := Link(sess, conn, p.out, func(pkt []byte) error {
		src, dst, ok := IPv4(pkt)
		if !ok || src != ip {
			return nil // не IPv4 или чужой адрес источника — отбрасываем
		}
		if r.isolate && r.prefix.Contains(dst) && dst != r.gw {
			return nil // клиенты не видят друг друга
		}
		_, err := r.tun.Write(pkt)
		return err
	}, keepalive)

	r.mu.Lock()
	if r.peers[ip] == p {
		delete(r.peers, ip)
	}
	r.mu.Unlock()
	return err
}

// Kick закрывает сессии клиентов, для которых keep вернула false.
func (r *Router) Kick(keep func(key string) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.peers {
		if !keep(p.key) {
			log.Printf("клиент %s… (%s) больше не разрешён — отключаю", p.key[:8], p.ip)
			p.conn.Close()
		}
	}
}

// Count — число подключённых клиентов.
func (r *Router) Count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.peers) }

// Run читает пакеты из TUN и отправляет их нужному клиенту.
func (r *Router) Run() error {
	buf := make([]byte, 65535)
	for {
		n, err := r.tun.Read(buf)
		if err != nil {
			return err
		}
		_, dst, ok := IPv4(buf[:n])
		if !ok {
			continue
		}
		r.mu.Lock()
		p := r.peers[dst]
		r.mu.Unlock()
		if p == nil {
			continue
		}
		select {
		case p.out <- append([]byte(nil), buf[:n]...):
		default: // клиент не успевает — пакет теряется
		}
	}
}
