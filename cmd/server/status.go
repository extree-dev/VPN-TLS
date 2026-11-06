package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/extree-dev/vpn-tls/internal/tunnel"
)

type status struct {
	Updated time.Time         `json:"updated"`
	Started time.Time         `json:"started"`
	Peers   []tunnel.PeerInfo `json:"peers"`
}

// writeStatus раз в 5 секунд сохраняет список подключённых клиентов в файл.
func writeStatus(path string, r *tunnel.Router) {
	st := status{Started: time.Now()}
	for {
		st.Updated, st.Peers = time.Now(), r.Snapshot()
		if data, err := json.Marshal(st); err == nil {
			if os.WriteFile(path+".tmp", data, 0o600) == nil {
				os.Rename(path+".tmp", path)
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func statusCmd(o *options) {
	log.SetFlags(0)
	data, err := os.ReadFile(o.statusFile)
	if err != nil {
		log.Fatalf("нет данных о статусе (%v) — сервер запущен?", err)
	}
	var st status
	if err := json.Unmarshal(data, &st); err != nil {
		log.Fatal(err)
	}
	if age := time.Since(st.Updated); age > 30*time.Second {
		fmt.Printf("ВНИМАНИЕ: статус не обновлялся %s — сервер, похоже, не работает\n\n", age.Round(time.Second))
	}
	fmt.Printf("сервер работает %s, клиентов онлайн: %d\n", dur(time.Since(st.Started)), len(st.Peers))
	if len(st.Peers) == 0 {
		return
	}
	sort.Slice(st.Peers, func(i, j int) bool { return st.Peers[i].IP < st.Peers[j].IP })
	fmt.Printf("\n%-14s %-11s %-16s %-10s %10s %10s\n", "ИМЯ", "АДРЕС", "ОТКУДА", "ОНЛАЙН", "ОТ НЕГО", "К НЕМУ")
	for _, p := range st.Peers {
		fmt.Printf("%-14s %-11s %-16s %-10s %10s %10s\n", p.Name, p.IP, p.Remote, dur(time.Since(p.Since)), size(p.RX), size(p.TX))
	}
}

func dur(d time.Duration) string {
	d = d.Round(time.Second)
	if h := int(d.Hours()); h >= 24 {
		return fmt.Sprintf("%dд %dч", h/24, h%24)
	} else if h > 0 {
		return fmt.Sprintf("%dч %dм", h, int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dм %dс", int(d.Minutes()), int(d.Seconds())%60)
}

func size(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f ГБ", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f МБ", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f КБ", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d Б", b)
}
