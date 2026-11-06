package transport

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/extree-dev/vpn-tls/internal/frame"
	"github.com/extree-dev/vpn-tls/internal/noise"
)

// DialConfig — параметры подключения клиента.
type DialConfig struct {
	Addr      string // host:port сервера
	SNI       string // имя сервера в TLS (домен); по умолчанию host из Addr
	Pin       string // SHA-256 отпечаток сертификата (для самоподписанного); пусто — обычная проверка
	Path      string // секретный путь туннеля на сервере, по умолчанию "/"
	Static    *ecdh.PrivateKey
	ServerPub *ecdh.PublicKey
}

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// Dial устанавливает TLS-соединение с отпечатком Chrome, проходит рукопожатие
// и возвращает шифрованную сессию, соединение (чтобы его можно было закрыть)
// и payload сервера с настройками.
func Dial(cfg DialConfig) (*noise.Session, net.Conn, []byte, error) { return dial(cfg) }

func dial(cfg DialConfig) (*noise.Session, net.Conn, []byte, error) {
	var conn net.Conn // закрывается при любой ошибке
	ok := false
	defer func() {
		if !ok && conn != nil {
			conn.Close()
		}
	}()
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, nil, nil, err
	}
	sni := cfg.SNI
	if sni == "" {
		sni = host
	}
	path := cfg.Path
	if path == "" {
		path = "/"
	}

	raw, err := net.DialTimeout("tcp", cfg.Addr, 10*time.Second)
	if err != nil {
		return nil, nil, nil, err
	}
	conn = raw
	tcfg := &utls.Config{ServerName: sni}
	if cfg.Pin != "" {
		pin := strings.ToLower(strings.ReplaceAll(cfg.Pin, ":", ""))
		tcfg.InsecureSkipVerify = true // проверяем сами, по отпечатку
		tcfg.VerifyPeerCertificate = func(certs [][]byte, _ [][]*x509.Certificate) error {
			if len(certs) == 0 || Fingerprint(certs[0]) != pin {
				return errors.New("отпечаток сертификата сервера не совпадает с -pin")
			}
			return nil
		}
	}
	uc := utls.UClient(raw, tcfg, utls.HelloChrome_Auto)
	conn = uc
	uc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := uc.Handshake(); err != nil {
		return nil, nil, nil, fmt.Errorf("TLS: %w", err)
	}
	if p := uc.ConnectionState().NegotiatedProtocol; p != "" && p != "http/1.1" {
		return nil, nil, nil, fmt.Errorf("сервер выбрал протокол %q, ожидался http/1.1", p)
	}

	in, msg1, err := noise.NewInitiator(cfg.Static, cfg.ServerPub, uint64(time.Now().UnixNano()))
	if err != nil {
		return nil, nil, nil, err
	}
	cookie := base64.RawURLEncoding.EncodeToString(withPadding(msg1))
	var wsKey [16]byte
	rand.Read(wsKey[:])
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + sni + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Pragma: no-cache\r\n" +
		"Cache-Control: no-cache\r\n" +
		"User-Agent: " + userAgent + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Origin: https://" + sni + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Accept-Encoding: gzip, deflate, br, zstd\r\n" +
		"Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7\r\n" +
		"Cookie: " + CookieName + "=" + cookie + "\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(wsKey[:]) + "\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, nil, nil, err
	}

	br := bufio.NewReaderSize(uc, 65536)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	if resp.StatusCode >= 500 {
		return nil, nil, nil, fmt.Errorf("сервер временно недоступен (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return nil, nil, nil, errors.New("сервер отклонил подключение (неверный ключ сервера или ключ клиента не добавлен в -allow)")
	}
	f, err := frame.Read(br, make([]byte, 4096))
	if err != nil || len(f) < 2 {
		return nil, nil, nil, errors.New("обрыв во время рукопожатия")
	}
	n := int(f[0])<<8 | int(f[1])
	if 2+n > len(f) {
		return nil, nil, nil, errors.New("неверный ответ сервера")
	}
	k, payload, err := in.Finish(f[2 : 2+n])
	if err != nil {
		return nil, nil, nil, err
	}
	uc.SetDeadline(time.Time{})
	rw := struct {
		io.Reader
		io.Writer
	}{br, uc}
	sess, err := noise.NewSession(k, rw, frame.Read)
	if err != nil {
		return nil, nil, nil, err
	}
	ok = true
	return sess, uc, payload, nil
}
