//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/extree-dev/vpn-tls/internal/config"
	"github.com/extree-dev/vpn-tls/internal/tun"
	"github.com/extree-dev/vpn-tls/internal/winnet"
	"github.com/extree-dev/vpn-tls/mobile"
)

const ifaceName = "VPN-TLS"

// controller — состояние подключения для окна.
type controller struct {
	profile string

	mu     sync.Mutex
	link   string
	status string // off, connecting, connected, reconnecting
	err    string
	t      *mobile.Tunnel
	dev    *tun.Device
	undo   func()
	gen    int // номер попытки: устаревшие события старого туннеля игнорируются
	since  time.Time
	tunIP  string

	// onChange вызывается после смены состояния (вне блокировки).
	onChange func(status, err string)
}

// State — то, что показывает окно.
type State struct {
	HasProfile bool     `json:"hasProfile"`
	Name       string   `json:"name"`
	Server     string   `json:"server"`
	Status     string   `json:"status"`
	Error      string   `json:"error"`
	Since      int64    `json:"since"` // начало сессии, мс Unix (0 — не подключено)
	RX         int64    `json:"rx"`
	TX         int64    `json:"tx"`
	TunnelIP   string   `json:"tunnelIp"`
	Settings   Settings `json:"settings"`
	Version    string   `json:"version"`
}

func newController(profile string) *controller {
	c := &controller{profile: profile, status: "off"}
	if l, err := loadProfile(profile); err == nil {
		c.link = l
	}
	return c
}

func (c *controller) state() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := State{HasProfile: c.link != "", Status: c.status, Error: c.err, TunnelIP: c.tunIP, Version: appVersion}
	if l, err := config.ParseLink(c.link); err == nil {
		s.Name, s.Server = l.Name, l.Addr
	}
	if c.t != nil {
		s.RX, s.TX = c.t.RxBytes(), c.t.TxBytes()
	}
	if !c.since.IsZero() {
		s.Since = c.since.UnixMilli()
	}
	return s
}

// changed сообщает о новом состоянии (вызывать без блокировки).
func (c *controller) changed() {
	c.mu.Lock()
	st, e, f := c.status, c.err, c.onChange
	c.mu.Unlock()
	if f != nil {
		f(st, e)
	}
}

func (c *controller) isOn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status != "off"
}

func (c *controller) save(link string) error {
	if _, err := config.ParseLink(link); err != nil {
		return errors.New("это не строка подключения vpntls://")
	}
	if err := saveProfile(c.profile, link); err != nil {
		return err
	}
	c.mu.Lock()
	c.link, c.err = link, ""
	c.mu.Unlock()
	return nil
}

func (c *controller) remove() {
	c.disconnect()
	os.Remove(c.profile)
	c.mu.Lock()
	c.link, c.err = "", ""
	c.mu.Unlock()
}

func (c *controller) toggle() {
	c.mu.Lock()
	on := c.status != "off"
	c.mu.Unlock()
	if on {
		c.disconnect()
	} else {
		go c.connect()
	}
}

func (c *controller) connect() {
	c.mu.Lock()
	if c.status != "off" || c.link == "" {
		c.mu.Unlock()
		return
	}
	c.gen++
	gen, link := c.gen, c.link
	c.status, c.err = "connecting", ""
	c.mu.Unlock()
	c.changed()

	fail := func(err error) {
		log.Printf("подключение: %v", err)
		c.disconnect()
		c.mu.Lock()
		c.err = humanError(err)
		c.mu.Unlock()
		c.changed()
	}

	dev, err := tun.Open(ifaceName)
	if err != nil {
		fail(err)
		return
	}
	c.mu.Lock()
	c.dev = dev
	c.mu.Unlock()

	t, err := mobile.Connect(link, writer{dev}, listener{c, gen})
	if err != nil {
		fail(err)
		return
	}
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()

	var s struct {
		IP     string   `json:"ip"`
		DNS    []string `json:"dns"`
		MTU    int      `json:"mtu"`
		Server string   `json:"server"`
	}
	if err := json.Unmarshal([]byte(t.Settings()), &s); err != nil {
		fail(err)
		return
	}
	if err := winnet.Configure(ifaceName, s.IP, s.MTU, s.DNS); err != nil {
		fail(err)
		return
	}
	server, err := netip.ParseAddr(s.Server)
	if err != nil {
		fail(err)
		return
	}
	undo, err := winnet.RouteAll(ifaceName, server)
	if err != nil {
		fail(err)
		return
	}
	c.mu.Lock()
	if c.gen != gen { // пока подключались, пользователь нажал «отключить»
		c.mu.Unlock()
		undo()
		return
	}
	c.undo = undo
	c.status, c.since, c.tunIP = "connected", time.Now(), s.IP
	c.mu.Unlock()
	c.changed()
	log.Printf("подключено: %s", t.Settings())

	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				return
			}
			t.WritePacket(buf[:n])
		}
	}()
}

func (c *controller) disconnect() {
	c.mu.Lock()
	t, dev, undo := c.t, c.dev, c.undo
	was := c.status
	c.t, c.dev, c.undo = nil, nil, nil
	c.status, c.since, c.tunIP = "off", time.Time{}, ""
	c.gen++
	c.mu.Unlock()
	if was != "off" {
		defer c.changed()
	}
	if t != nil {
		t.Close()
	}
	if undo != nil {
		undo()
	}
	if dev != nil {
		dev.Close() // вместе с адаптером уходят его адрес, DNS и маршруты
	}
}

type writer struct{ d *tun.Device }

func (w writer) WritePacket(p []byte) { w.d.Write(p) }

type listener struct {
	c   *controller
	gen int
}

func (l listener) OnStatus(state, detail string) {
	c := l.c
	c.mu.Lock()
	if c.gen != l.gen {
		c.mu.Unlock()
		return
	}
	prev := c.status
	switch state {
	case "connected":
		if c.undo != nil {
			c.status = "connected"
		}
		c.err = ""
	case "reconnecting":
		c.status = "reconnecting"
		c.err = humanError(errors.New(detail))
	case "failed":
		c.mu.Unlock()
		log.Printf("отказ: %s", detail)
		go func() {
			c.disconnect()
			c.mu.Lock()
			c.err = humanError(errors.New(detail))
			c.mu.Unlock()
			c.changed()
		}()
		return
	}
	now := c.status
	c.mu.Unlock()
	if now != prev {
		c.changed()
	}
}

// humanError — понятный текст для частых ошибок.
func humanError(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "отклонил"):
		return "Сервер отклонил подключение: ключ отозван или строка подключения устарела."
	case strings.Contains(s, "no such host"), strings.Contains(s, "нет IPv4"):
		return "Не удаётся найти сервер. Проверьте подключение к интернету."
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "connection refused"), strings.Contains(s, "временно недоступен"):
		return "Сервер не отвечает. Повторяю попытку…"
	case strings.Contains(s, "x509"), strings.Contains(s, "certificate"):
		return "Не удалось проверить сертификат сервера."
	case strings.Contains(s, "wintun"):
		return "Не найден wintun.dll рядом с программой."
	}
	return s
}
