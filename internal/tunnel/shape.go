package tunnel

import (
	"hash/fnv"
	mrand "math/rand/v2"
	"time"

	"github.com/extree-dev/vpn-tls/internal/noise"
)

// Маскировка трафика.
//
// TLS внутри TLS. Когда через туннель открывается HTTPS-сайт, внутри нашего
// TLS идёт ещё одно TLS-рукопожатие. Его пакеты (ClientHello, ServerHello,
// сертификаты) имеют узнаваемые размеры и порядок, и по размерам внешних
// TLS-записей это можно заметить. Поэтому первые пакеты каждого внутреннего
// соединения дополняются до случайного крупного размера и отправляются
// несколькими отдельными записями.
//
// Остальной трафик получает небольшой случайный padding, а при потоке
// пакетов несколько кадров склеиваются в одну запись.

// heavyPackets — сколько первых пакетов каждого внутреннего соединения маскировать.
const heavyPackets = 10

// flows считает пакеты внутренних соединений (TCP/UDP), чтобы узнать первые.
type flows struct{ seen map[uint64]uint8 }

// heavy — нужно ли маскировать этот пакет особенно сильно.
func (f *flows) heavy(p []byte) bool {
	if len(p) < 20 || p[0]>>4 != 4 {
		return false
	}
	ihl := int(p[0]&0x0f) * 4
	proto := p[9]
	if (proto != 6 && proto != 17) || len(p) < ihl+4 {
		return false
	}
	h := fnv.New64a()
	h.Write([]byte{proto})
	h.Write(p[12:20])       // адреса
	h.Write(p[ihl : ihl+4]) // порты
	key := h.Sum64()

	if f.seen == nil || len(f.seen) > 8192 {
		f.seen = map[uint64]uint8{}
	}
	if proto == 6 && len(p) >= ihl+14 && p[ihl+13]&0x02 != 0 { // TCP SYN — новое соединение
		f.seen[key] = 0
	}
	n := f.seen[key]
	if n >= heavyPackets {
		return false
	}
	f.seen[key] = n + 1
	return true
}

// heavyPad — padding для «первых» пакетов: кадр вырастает до случайного
// размера 600…1400 байт; уже крупные пакеты получают немного сверху.
func heavyPad(n int) int {
	target := 600 + mrand.IntN(800)
	if n+64 >= target {
		return mrand.IntN(64)
	}
	return target - n
}

func sendOpts(f *flows, p []byte, queued int) noise.SendOpts {
	if f.heavy(p) {
		return noise.SendOpts{Pad: heavyPad(len(p)), Fragment: true, Flush: true}
	}
	// Пока в очереди есть ещё пакеты, кадры копятся и уходят одной записью.
	return noise.SendOpts{Pad: noise.RandomPad(), Flush: queued == 0}
}

// jitter — случайный интервал keepalive: от половины до полутора базового.
func jitter(base time.Duration) time.Duration {
	return base/2 + time.Duration(mrand.Int64N(int64(base)))
}
