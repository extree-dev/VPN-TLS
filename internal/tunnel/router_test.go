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
