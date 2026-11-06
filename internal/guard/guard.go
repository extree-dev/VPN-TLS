// Package guard — защита сервера: от повтора рукопожатий и от перебора.
package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"time"
)

// ErrReplay — рукопожатие с меткой времени не новее уже принятой: повтор.
var ErrReplay = errors.New("повтор старого рукопожатия")

// SkewError — часы клиента расходятся с сервером сильнее допустимого.
type SkewError struct{ Diff time.Duration }

func (e SkewError) Error() string {
	return fmt.Sprintf("время клиента отличается от сервера на %s — проверьте часы на устройстве", e.Diff.Round(time.Second))
}

// Replay не даёт повторить перехваченное рукопожатие.
//
// Первое сообщение клиента содержит метку времени. Сервер принимает её, только
// если она (1) близка к текущему времени и (2) новее последней принятой от
// этого клиента. Последние метки сохраняются в файл, поэтому перезапуск
// сервера не открывает окно для повтора.
type Replay struct {
	File    string
	MaxSkew time.Duration

	mu   sync.Mutex
	last map[string]uint64
}

// Load читает сохранённые метки (отсутствие файла — не ошибка).
func (r *Replay) Load() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = map[string]uint64{}
	if r.File == "" {
		return nil
	}
	data, err := os.ReadFile(r.File)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &r.last)
}

// Check проверяет и запоминает метку времени клиента key (текстовый ключ: он попадает в JSON).
func (r *Replay) Check(key string, ts uint64, now time.Time) error {
	diff := time.Duration(int64(ts) - now.UnixNano())
	if ts > math.MaxInt64 || diff > r.MaxSkew || -diff > r.MaxSkew {
		return SkewError{diff}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		r.last = map[string]uint64{}
	}
	if ts <= r.last[key] {
		return ErrReplay
	}
	r.last[key] = ts
	return r.save()
}

func (r *Replay) save() error {
	if r.File == "" {
		return nil
	}
	data, _ := json.Marshal(r.last)
	tmp := r.File + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.File)
}

// Limiter ограничивает частоту попыток подключения с одного IP
// (token bucket: Burst попыток сразу, дальше одна раз в Every).
type Limiter struct {
	Burst int
	Every time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
	sweep   time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

// Allow — можно ли принять ещё одну попытку с ip.
func (l *Limiter) Allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[string]*bucket{}
	}
	if now.Sub(l.sweep) > time.Minute { // убираем давно молчащие IP
		for k, b := range l.buckets {
			if now.Sub(b.at) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.sweep = now
	}
	b := l.buckets[ip]
	if b == nil {
		b = &bucket{tokens: float64(l.Burst), at: now}
		l.buckets[ip] = b
	}
	b.tokens = math.Min(float64(l.Burst), b.tokens+now.Sub(b.at).Seconds()/l.Every.Seconds())
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
