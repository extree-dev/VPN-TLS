package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestLinkRoundTrip(t *testing.T) {
	ck, _ := ecdh.X25519().GenerateKey(rand.Reader)
	sk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	l := &Link{ClientKey: ck, ServerPub: sk.PublicKey(), Addr: "vpn.extree.tech:443",
		Path: "/api/abc", SNI: "vpn.extree.tech", Pin: "aa11", Name: "phone"}
	got, err := ParseLink(l.String())
	if err != nil {
		t.Fatal(err)
	}
	if !got.ClientKey.Equal(ck) || !got.ServerPub.Equal(sk.PublicKey()) || got.Addr != l.Addr ||
		got.Path != l.Path || got.SNI != l.SNI || got.Pin != l.Pin || got.Name != l.Name {
		t.Fatalf("mismatch: %+v", got)
	}
}

func TestParseClient(t *testing.T) {
	if _, err := ParseClient([]byte(`{"ip":"10.8.0.2/24","dns":["1.1.1.1"],"mtu":1400,"ka":15}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"ip":"x"}`, `{"ip":"10.8.0.2/24","dns":["evil"]}`, `{"ip":"fd00::2/64"}`} {
		if _, err := ParseClient([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
