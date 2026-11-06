package transport

import (
	"bufio"
	"crypto/ecdh"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/extree-dev/vpn-tls/internal/guard"
	"github.com/extree-dev/vpn-tls/internal/noise"
)

type env struct {
	srv         *httptest.Server
	server, cli *ecdh.PrivateKey
	replayFile  string
	sessions    chan string
}

func newEnv(t *testing.T, replayFile string, server, cli *ecdh.PrivateKey, limit *guard.Limiter) *env {
	t.Helper()
	e := &env{server: server, cli: cli, replayFile: replayFile, sessions: make(chan string, 10)}
	r := &guard.Replay{File: replayFile, MaxSkew: time.Minute}
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	h := &Handler{
		Priv:     server,
		Path:     "/tun",
		Fallback: StubSite,
		Allowed:  func(p []byte) bool { return string(p) == string(cli.PublicKey().Bytes()) },
		Payload:  func(*ecdh.PublicKey) ([]byte, error) { return []byte("{}"), nil },
		OnSession: func(_ *noise.Session, c net.Conn, _ *ecdh.PublicKey, remote string) {
			e.sessions <- remote
			c.Close()
		},
		Replay:     r,
		Limit:      limit,
		TrustProxy: true,
	}
	e.srv = httptest.NewServer(h)
	t.Cleanup(e.srv.Close)
	return e
}

// try отправляет запрос с готовым msg1 и возвращает код ответа.
func (e *env) try(t *testing.T, msg1 []byte, xff string) int {
	t.Helper()
	c, err := net.Dial("tcp", e.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := "GET /tun HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
		"X-Forwarded-For: " + xff + "\r\n" +
		"Cookie: " + CookieName + "=" + base64.RawURLEncoding.EncodeToString(msg1) + "\r\n\r\n"
	c.Write([]byte(req))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode
}

func msg1(t *testing.T, cli, server *ecdh.PrivateKey, at time.Time) []byte {
	_, m, err := noise.NewInitiator(cli, server.PublicKey(), uint64(at.UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestReplayAndRestart(t *testing.T) {
	server, _ := noise.GenerateKey()
	cli, _ := noise.GenerateKey()
	file := filepath.Join(t.TempDir(), "replay.json")
	e := newEnv(t, file, server, cli, nil)

	m := msg1(t, cli, server, time.Now())
	if code := e.try(t, m, "203.0.113.7"); code != http.StatusSwitchingProtocols {
		t.Fatalf("первое подключение: %d", code)
	}
	if got := <-e.sessions; got != "203.0.113.7" {
		t.Fatalf("IP клиента %q, ожидался из X-Forwarded-For", got)
	}
	if code := e.try(t, m, "203.0.113.7"); code == http.StatusSwitchingProtocols {
		t.Fatal("повтор того же рукопожатия принят")
	}
	if code := e.try(t, msg1(t, cli, server, time.Now().Add(-10*time.Minute)), "203.0.113.7"); code == http.StatusSwitchingProtocols {
		t.Fatal("рукопожатие со старым временем принято")
	}

	// «Перезапуск» сервера: новый обработчик, тот же файл.
	e2 := newEnv(t, file, server, cli, nil)
	if code := e2.try(t, m, "203.0.113.7"); code == http.StatusSwitchingProtocols {
		t.Fatal("повтор принят после перезапуска")
	}
	if code := e2.try(t, msg1(t, cli, server, time.Now()), "203.0.113.7"); code != http.StatusSwitchingProtocols {
		t.Fatalf("новое подключение после перезапуска: %d", code)
	}
}

func TestRateLimit(t *testing.T) {
	server, _ := noise.GenerateKey()
	cli, _ := noise.GenerateKey()
	e := newEnv(t, "", server, cli, &guard.Limiter{Burst: 3, Every: time.Minute})
	junk := make([]byte, noise.Msg1Size)
	for i := 0; i < 3; i++ {
		e.try(t, junk, "198.51.100.1") // мусор от сканера
	}
	if code := e.try(t, msg1(t, cli, server, time.Now()), "198.51.100.1"); code == http.StatusSwitchingProtocols {
		t.Fatal("после исчерпания лимита подключение прошло")
	}
	if code := e.try(t, msg1(t, cli, server, time.Now()), "198.51.100.2"); code != http.StatusSwitchingProtocols {
		t.Fatalf("клиент с другого IP: %d", code)
	}
}
