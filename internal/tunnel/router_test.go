package tunnel

import (
	"net/netip"
	"testing"
)

func TestLease(t *testing.T) {
	r := NewRouter(nil, netip.MustParsePrefix("10.8.0.1/24"), true)
	fixed := netip.MustParseAddr("10.8.0.2")
	res := map[netip.Addr]bool{fixed: true}

	a, _ := r.Lease("A", netip.Addr{}, res)
	if a.String() != "10.8.0.3" {
		t.Fatalf("A got %s, want 10.8.0.3 (.1 — сервер, .2 закреплён)", a)
	}
	b, _ := r.Lease("B", fixed, res)
	if b != fixed {
		t.Fatalf("B got %s", b)
	}
	if a2, _ := r.Lease("A", netip.Addr{}, res); a2 != a {
		t.Fatalf("A lease not stable: %s", a2)
	}
	if _, err := r.Lease("C", netip.MustParseAddr("192.168.1.5"), res); err == nil {
		t.Fatal("accepted address outside subnet")
	}
	for _, bad := range []string{"10.8.0.0", "10.8.0.1", "10.8.0.255"} {
		if r.usable(netip.MustParseAddr(bad)) {
			t.Fatalf("%s must not be usable", bad)
		}
	}
}

func tcpPacket(sport, dport uint16, syn bool) []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	p[9] = 6
	copy(p[12:16], []byte{10, 8, 0, 2})
	copy(p[16:20], []byte{1, 1, 1, 1})
	p[20], p[21] = byte(sport>>8), byte(sport)
	p[22], p[23] = byte(dport>>8), byte(dport)
	if syn {
		p[33] = 0x02
	}
	return p
}

func TestFlowsHeavy(t *testing.T) {
	var f flows
	a := tcpPacket(40000, 443, true)
	for i := 0; i < heavyPackets; i++ {
		if !f.heavy(a) {
			t.Fatalf("пакет %d соединения должен маскироваться", i+1)
		}
		a = tcpPacket(40000, 443, false)
	}
	if f.heavy(a) {
		t.Fatal("после первых пакетов маскировка должна выключаться")
	}
	if !f.heavy(tcpPacket(40001, 443, false)) {
		t.Fatal("новое соединение (другой порт) должно маскироваться")
	}
	if !f.heavy(tcpPacket(40000, 443, true)) {
		t.Fatal("новый SYN на том же порту должен сбрасывать счётчик")
	}
	if f.heavy([]byte{0x60, 0, 0, 0}) {
		t.Fatal("не-IPv4 не маскируется")
	}
	for i := 0; i < 1000; i++ {
		if n := heavyPad(100); 100+n < 600 || 100+n > 1400 {
			t.Fatalf("размер после padding %d вне 600…1400", 100+n)
		}
	}
}
