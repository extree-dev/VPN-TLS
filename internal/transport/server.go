// Package transport прячет туннель внутри обычного HTTPS.
//
// Снаружи это TLS-соединение и запрос на установку WebSocket (HTTP Upgrade)
// с cookie. Внутри cookie — первое сообщение Noise. Если оно верное и ключ
// клиента разрешён, сервер отвечает 101 Switching Protocols, и дальше по
// тому же соединению идут шифрованные кадры. Во всех остальных случаях
// запрос получает обычный сайт (fallback), поэтому сканер или ТСПУ,
// прощупывающие сервер, видят просто веб-сервер.
//
// Upgrade проходит через обычные обратные прокси (Caddy, nginx), поэтому
// сервер можно поставить за прокси с настоящим доменом и сертификатом.
package transport

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/extree-dev/vpn-tls/internal/frame"
	"github.com/extree-dev/vpn-tls/internal/guard"
	"github.com/extree-dev/vpn-tls/internal/noise"
)

// CookieName — имя cookie с рукопожатием. Выглядит как обычная сессионная cookie.
const CookieName = "sid"

// Handler — http.Handler, который распознаёт клиентов туннеля.
type Handler struct {
	Priv     *ecdh.PrivateKey
	Allowed  func(pub []byte) bool // разрешён ли публичный ключ клиента
	Fallback http.Handler          // что показывать всем остальным
	Path     string                // секретный путь туннеля; пусто — любой путь
	// Payload возвращает настройки для клиента (адрес, DNS…), которые уйдут
	// во втором сообщении рукопожатия. Ошибка — отказ в подключении.
	Payload func(client *ecdh.PublicKey) ([]byte, error)
	// OnSession вызывается для каждого авторизованного клиента и должна
	// блокироваться, пока сессия жива. remote — реальный IP клиента.
	OnSession func(sess *noise.Session, conn net.Conn, client *ecdh.PublicKey, remote string)

	Replay     *guard.Replay  // защита от повтора рукопожатия
	Limit      *guard.Limiter // ограничение попыток с одного IP (nil — без ограничения)
	TrustProxy bool           // брать IP клиента из X-Forwarded-For (сервер за Caddy)
	Logf       func(format string, args ...any)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if (h.Path != "" && r.URL.Path != h.Path) || !isUpgrade(r) {
		h.Fallback.ServeHTTP(w, r)
		return
	}
	remote := h.clientIP(r)
	if h.Limit != nil && !h.Limit.Allow(remote, time.Now()) {
		h.Fallback.ServeHTTP(w, r) // слишком часто — снаружи выглядит как обычный ответ сайта
		return
	}
	req, ok := h.authenticate(r, remote)
	if !ok {
		h.Fallback.ServeHTTP(w, r)
		return
	}
	payload, err := h.Payload(req.ClientPub)
	if err != nil {
		h.Fallback.ServeHTTP(w, r)
		return
	}
	resp, k, err := req.Accept(payload)
	if err != nil {
		h.Fallback.ServeHTTP(w, r)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		h.Fallback.ServeHTTP(w, r)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Time{})

	io.WriteString(brw, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: "+wsAccept(r.Header.Get("Sec-WebSocket-Key"))+"\r\n\r\n")
	if err := frame.Write(brw, withPadding(lengthPrefixed(resp))); err != nil {
		return
	}
	if err := brw.Flush(); err != nil {
		return
	}
	rw := struct {
		io.Reader
		io.Writer
	}{brw.Reader, conn}
	sess, err := noise.NewSession(k, rw, frame.Write, frame.Read)
	if err != nil {
		return
	}
	h.OnSession(sess, conn, req.ClientPub, remote)
}

func isUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// wsAccept — значение Sec-WebSocket-Accept по RFC 6455.
func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (h *Handler) authenticate(r *http.Request, remote string) (*noise.Request, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) < noise.Msg1Size {
		return nil, false
	}
	req, err := noise.ReadRequest(h.Priv, raw[:noise.Msg1Size])
	if err != nil {
		return nil, false
	}
	if !h.Allowed(req.ClientPub.Bytes()) {
		return nil, false
	}
	if err := h.Replay.Check(base64.StdEncoding.EncodeToString(req.ClientPub.Bytes()), req.Timestamp, time.Now()); err != nil {
		h.logf("%s (%s…): отклонён: %v", remote, keyPrefix(req.ClientPub), err)
		return nil, false
	}
	return req, true
}

// clientIP — реальный адрес клиента. За обратным прокси он в последнем
// элементе X-Forwarded-For (его дописывает сам прокси).
func (h *Handler) clientIP(r *http.Request) string {
	if h.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *Handler) logf(format string, args ...any) {
	if h.Logf != nil {
		h.Logf(format, args...)
	}
}

func keyPrefix(p *ecdh.PublicKey) string {
	return base64.StdEncoding.EncodeToString(p.Bytes())[:8]
}

// lengthPrefixed добавляет 2 байта длины, чтобы получатель отделил сообщение от padding.
func lengthPrefixed(msg []byte) []byte {
	out := make([]byte, 2+len(msg))
	out[0], out[1] = byte(len(msg)>>8), byte(len(msg))
	copy(out[2:], msg)
	return out
}

// withPadding дописывает к сообщению 16–112 случайных байт, чтобы размер
// рукопожатия не был постоянным. Получатель берёт только нужный префикс.
func withPadding(msg []byte) []byte {
	var n [1]byte
	rand.Read(n[:])
	pad := make([]byte, 16+int(n[0])%97)
	rand.Read(pad)
	return append(append([]byte(nil), msg...), pad...)
}

// StubSite — простая страница-заглушка, если -fallback не задан.
var StubSite = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound) // пустой 404, как у Caddy file_server
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Welcome</title></head>
<body><h1>It works</h1><p>This site is under construction.</p></body></html>
`)
})

// QuietLog — логгер для http.Server, глушащий шум от сканеров (ошибки TLS-рукопожатий).
var QuietLog = log.New(io.Discard, "", 0)
