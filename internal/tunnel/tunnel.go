// Package tunnel гоняет пакеты между TUN и шифрованными сессиями:
// keepalive, таймауты, маршрутизация между несколькими клиентами на сервере.
package tunnel

import (
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/extree-dev/vpn-tls/internal/noise"
)

// Link обслуживает одну сессию: отправляет пакеты из out (и keepalive, если
// канал простаивает), принятые пакеты отдаёт в deliver. Возвращается, когда
// соединение рвётся или от собеседника ничего не приходит 3×keepalive.
func Link(sess *noise.Session, conn net.Conn, out <-chan []byte, deliver func([]byte) error, keepalive time.Duration) error {
	done := make(chan struct{})
	werr := make(chan error, 1)
	go func() {
		t := time.NewTicker(keepalive / 3)
		defer t.Stop()
		last := time.Now()
		for {
			var err error
			select {
			case <-done:
				werr <- nil
				return
			case p := <-out:
				err = sess.WritePacket(p)
				last = time.Now()
			case <-t.C:
				if time.Since(last) >= keepalive {
					err = sess.WriteKeepalive()
					last = time.Now()
				}
			}
			if err != nil {
				conn.Close()
				werr <- err
				return
			}
		}
	}()

	timeout := 3*keepalive + 5*time.Second
	buf := make([]byte, 65535)
	var rerr error
	for {
		conn.SetReadDeadline(time.Now().Add(timeout))
		p, err := sess.ReadPacket(buf)
		if err != nil {
			rerr = err
			break
		}
		if len(p) == 0 {
			continue // keepalive
		}
		if err := deliver(p); err != nil {
			rerr = err
			break
		}
	}
	close(done)
	conn.Close()
	if err := <-werr; rerr == nil {
		rerr = err
	}
	return rerr
}

// ReadTUN читает пакеты из TUN в канал, пока TUN не закроется.
// Канал общий для всех сессий клиента: пакеты не теряются между переподключениями.
func ReadTUN(tun io.Reader, out chan<- []byte) error {
	buf := make([]byte, 65535)
	for {
		n, err := tun.Read(buf)
		if err != nil {
			close(out)
			return err
		}
		select {
		case out <- append([]byte(nil), buf[:n]...):
		default: // очередь переполнена — пакет теряется, как в обычной сети
		}
	}
}

// IPv4 — адреса источника и назначения IPv4-пакета; ok=false для прочих пакетов.
func IPv4(p []byte) (src, dst netip.Addr, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return src, dst, false
	}
	return netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20])), true
}
