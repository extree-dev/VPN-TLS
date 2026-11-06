// Package config — настройки, которые сервер выдаёт клиенту при подключении,
// и строка подключения vpntls://.
package config

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Client — настройки клиента. Передаются зашифрованными во втором сообщении
// рукопожатия, поэтому подделать их по дороге нельзя.
type Client struct {
	Addr      string   `json:"ip"`  // адрес клиента в туннеле, CIDR: 10.8.0.2/24
	Gateway   string   `json:"gw"`  // адрес сервера в туннеле
	DNS       []string `json:"dns"` // DNS-серверы, которые стоит использовать в туннеле
	MTU       int      `json:"mtu"`
	Keepalive int      `json:"ka"` // интервал keepalive, секунды
}

func (c *Client) Marshal() []byte { b, _ := json.Marshal(c); return b }

// ParseClient разбирает и проверяет настройки от сервера.
func ParseClient(b []byte) (*Client, error) {
	var c Client
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("настройки от сервера: %w", err)
	}
	p, err := netip.ParsePrefix(c.Addr)
	if err != nil || !p.Addr().Is4() {
		return nil, fmt.Errorf("неверный адрес от сервера: %q", c.Addr)
	}
	for _, d := range c.DNS {
		if _, err := netip.ParseAddr(d); err != nil {
			return nil, fmt.Errorf("неверный DNS от сервера: %q", d)
		}
	}
	if c.MTU < 576 || c.MTU > 9000 {
		c.MTU = 1400
	}
	if c.Keepalive <= 0 || c.Keepalive > 300 {
		c.Keepalive = 15
	}
	return &c, nil
}

// Link — всё, что нужно клиенту для подключения.
//
//	vpntls://<ключ клиента>@host:port/path?pub=<ключ сервера>&sni=…&pin=…#имя
//
// Строка содержит приватный ключ клиента: это секрет, как пароль.
type Link struct {
	ClientKey *ecdh.PrivateKey
	ServerPub *ecdh.PublicKey
	Addr      string // host:port
	Path      string
	SNI       string
	Pin       string
	Name      string
}

var b64 = base64.RawURLEncoding

func (l *Link) String() string {
	q := url.Values{}
	q.Set("pub", b64.EncodeToString(l.ServerPub.Bytes()))
	if l.SNI != "" {
		q.Set("sni", l.SNI)
	}
	if l.Pin != "" {
		q.Set("pin", l.Pin)
	}
	u := url.URL{
		Scheme:   "vpntls",
		User:     url.User(b64.EncodeToString(l.ClientKey.Bytes())),
		Host:     l.Addr,
		Path:     l.Path,
		RawQuery: q.Encode(),
		Fragment: l.Name,
	}
	return u.String()
}

// ParseLink разбирает строку подключения.
func ParseLink(s string) (*Link, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "vpntls" || u.User == nil || u.Host == "" {
		return nil, errors.New("это не строка подключения vpntls://")
	}
	ck, err := b64.DecodeString(u.User.Username())
	if err != nil {
		return nil, fmt.Errorf("ключ клиента: %w", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(ck)
	if err != nil {
		return nil, fmt.Errorf("ключ клиента: %w", err)
	}
	sp, err := b64.DecodeString(u.Query().Get("pub"))
	if err != nil {
		return nil, fmt.Errorf("ключ сервера: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(sp)
	if err != nil {
		return nil, fmt.Errorf("ключ сервера: %w", err)
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return &Link{
		ClientKey: key, ServerPub: pub, Addr: u.Host, Path: path,
		SNI: u.Query().Get("sni"), Pin: u.Query().Get("pin"), Name: u.Fragment,
	}, nil
}
