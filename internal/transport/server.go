// Package transport прячет туннель внутри обычного HTTPS.
//
// Снаружи это TLS-соединение на 443 и HTTP/1.1-запрос с cookie. Внутри cookie —
// первое сообщение Noise. Если оно верное и ключ клиента разрешён, сервер
// отвечает 200 и дальше по тому же соединению идут шифрованные кадры.
// Во всех остальных случаях запрос получает обычный сайт (fallback), поэтому
// сканер или ТСПУ, прощупывающие сервер, видят просто веб-сервер.
package transport

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/extree-dev/vpn-tls/internal/frame"
	"github.com/extree-dev/vpn-tls/internal/keys"
	"github.com/extree-dev/vpn-tls/internal/noise"
)

// CookieName — имя cookie с рукопожатием. Выглядит как обычная сессионная cookie.
const CookieName = "sid"

// Handler — http.Handler, который распознаёт клиентов туннеля.
type Handler struct {
	Priv     *ecdh.PrivateKey
	Allowed  map[string]bool // ключ: байты публичного ключа клиента
	Fallback http.Handler    // что показывать всем остальным
	// OnSession вызывается для каждого авторизованного клиента и должна
	// блокироваться, пока сессия жива.
	OnSession func(sess *noise.Session, conn net.Conn, client string)

	mu     sync.Mutex
	lastTS map[string]uint64
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, ok := h.authenticate(r)
	if !ok {
		h.Fallback.ServeHTTP(w, r)
		return
	}
	resp, k, err := req.Accept()
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

	io.WriteString(brw, "HTTP/1.1 200 OK\r\n"+
		"Content-Type: application/octet-stream\r\n"+
		"Cache-Control: no-store\r\n"+
		"Date: "+time.Now().UTC().Format(http.TimeFormat)+"\r\n\r\n")
	if err := frame.Write(brw, withPadding(resp)); err != nil {
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
	h.OnSession(sess, conn, keys.EncodePublic(req.ClientPub))
}

func (h *Handler) authenticate(r *http.Request) (*noise.Request, bool) {
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
	id := string(req.ClientPub.Bytes())
	if !h.Allowed[id] {
		return nil, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastTS == nil {
		h.lastTS = map[string]uint64{}
	}
	if req.Timestamp <= h.lastTS[id] {
		return nil, false // повтор старого рукопожатия
	}
	h.lastTS[id] = req.Timestamp
	return req, true
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
		http.NotFound(w, r)
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
