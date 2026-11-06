// Package clients — список разрешённых клиентов (файл clients.txt).
//
// Формат строки:  <публичный ключ base64> [адрес в туннеле] [# имя]
//
//	AVS2yIvb44LpJnadb6UDYZgFH8gFl63vS+YG/wkNj2Y= 10.8.0.2 # laptop
//	qpP9kMUCUFszB57xeBAXxUaetUIL9L0StoNdkS/8Y0M=          # адрес выдаётся автоматически
package clients

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/extree-dev/vpn-tls/internal/keys"
)

// Entry — один клиент.
type Entry struct {
	Pub  []byte     // публичный ключ X25519
	Key  string     // он же в base64
	IP   netip.Addr // закреплённый адрес; нулевой — выдавать из пула
	Name string
}

// Parse разбирает содержимое файла. Неверные строки пропускаются с сообщением в лог.
func Parse(data string) []Entry {
	var out []Entry
	for n, line := range strings.Split(data, "\n") {
		name := ""
		if i := strings.IndexByte(line, '#'); i >= 0 {
			name = strings.TrimSpace(line[i+1:])
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		pub, err := keys.ParsePublic(f[0])
		if err != nil {
			log.Printf("clients: строка %d: неверный ключ: %v", n+1, err)
			continue
		}
		e := Entry{Pub: pub.Bytes(), Key: keys.EncodePublic(pub), Name: name}
		if len(f) > 1 {
			ip, err := netip.ParseAddr(f[1])
			if err != nil || !ip.Is4() {
				log.Printf("clients: строка %d: неверный адрес %q", n+1, f[1])
				continue
			}
			e.IP = ip
		}
		out = append(out, e)
	}
	return out
}

// Format — строка файла для клиента.
func (e Entry) Format() string {
	s := e.Key
	if e.IP.IsValid() {
		s += " " + e.IP.String()
	}
	if e.Name != "" {
		s += " # " + e.Name
	}
	return s
}

// Append дописывает клиента в файл.
func Append(path string, e Entry) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, e.Format())
	return err
}

// Remove удаляет из файла клиентов с данным именем или ключом. Возвращает число удалённых.
func Remove(path, nameOrKey string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var keep []string
	removed := 0
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		es := Parse(line)
		if len(es) == 1 && (es[0].Name == nameOrKey || es[0].Key == nameOrKey) {
			removed++
			continue
		}
		keep = append(keep, line)
	}
	if removed == 0 {
		return 0, nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(keep, "\n")+"\n"), 0o600); err != nil {
		return 0, err
	}
	return removed, os.Rename(tmp, path)
}

// Store — список клиентов из файла (и флага), перечитывается при изменении файла.
type Store struct {
	File  string
	Extra string // дополнительные ключи через запятую (флаг -allow)

	mu      sync.Mutex
	mtime   time.Time
	size    int64
	loaded  bool
	byKey   map[string]Entry
	changed func()
}

// OnChange задаёт функцию, вызываемую после каждого перечитывания файла.
func (s *Store) OnChange(f func()) { s.mu.Lock(); s.changed = f; s.mu.Unlock() }

// Lookup ищет клиента по публичному ключу.
func (s *Store) Lookup(pub []byte) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload()
	e, ok := s.byKey[string(pub)]
	return e, ok
}

// Entries — все клиенты.
func (s *Store) Entries() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload()
	out := make([]Entry, 0, len(s.byKey))
	for _, e := range s.byKey {
		out = append(out, e)
	}
	return out
}

// Refresh проверяет файл и перечитывает его при изменении.
func (s *Store) Refresh() { s.mu.Lock(); s.reload(); s.mu.Unlock() }

func (s *Store) reload() {
	var mtime time.Time
	var size int64
	if s.File != "" {
		if st, err := os.Stat(s.File); err == nil {
			mtime, size = st.ModTime(), st.Size()
		}
	}
	if s.loaded && mtime.Equal(s.mtime) && size == s.size {
		return
	}
	var data []byte
	if s.File != "" {
		var err error
		if data, err = os.ReadFile(s.File); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("%s: %v", s.File, err)
		}
	}
	text := strings.ReplaceAll(s.Extra, ",", "\n") + "\n" + string(data)
	by := map[string]Entry{}
	for _, e := range Parse(text) {
		by[string(e.Pub)] = e
	}
	first := !s.loaded
	s.byKey, s.mtime, s.size, s.loaded = by, mtime, size, true
	if !first {
		log.Printf("список клиентов обновлён: %d", len(by))
		if s.changed != nil {
			go s.changed()
		}
	}
}
