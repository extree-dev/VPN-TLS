package guard

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestReplay(t *testing.T) {
	file := filepath.Join(t.TempDir(), "replay.json")
	now := time.Now()
	ts := uint64(now.UnixNano())
	r := &Replay{File: file, MaxSkew: 5 * time.Minute}
	r.Load()
	if err := r.Check("A", ts, now); err != nil {
		t.Fatal(err)
	}
	if err := r.Check("A", ts, now); !errors.Is(err, ErrReplay) {
		t.Fatalf("повтор принят: %v", err)
	}
	if err := r.Check("B", ts, now); err != nil {
		t.Fatalf("другой клиент с той же меткой: %v", err)
	}
	var skew SkewError
	if err := r.Check("A", uint64(now.Add(-10*time.Minute).UnixNano()), now); !errors.As(err, &skew) {
		t.Fatalf("старая метка принята: %v", err)
	}
	if err := r.Check("A", uint64(now.Add(10*time.Minute).UnixNano()), now); !errors.As(err, &skew) {
		t.Fatalf("метка из будущего принята: %v", err)
	}

	// После «перезапуска» сервер помнит последнюю метку.
	r2 := &Replay{File: file, MaxSkew: 5 * time.Minute}
	if err := r2.Load(); err != nil {
		t.Fatal(err)
	}
	if err := r2.Check("A", ts, now); !errors.Is(err, ErrReplay) {
		t.Fatalf("повтор после перезапуска принят: %v", err)
	}
	if err := r2.Check("A", ts+1, now); err != nil {
		t.Fatal(err)
	}
}

func TestLimiter(t *testing.T) {
	l := &Limiter{Burst: 3, Every: 10 * time.Second}
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4", now) {
			t.Fatalf("попытка %d отклонена", i+1)
		}
	}
	if l.Allow("1.2.3.4", now) {
		t.Fatal("4-я попытка подряд пропущена")
	}
	if !l.Allow("5.6.7.8", now) {
		t.Fatal("другой IP отклонён")
	}
	if !l.Allow("1.2.3.4", now.Add(11*time.Second)) {
		t.Fatal("через 10 с попытка не восстановилась")
	}
}
