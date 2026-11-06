package noise

import (
	"bytes"
	"net"
	"testing"

	"github.com/extree-dev/vpn-tls/internal/frame"
)

func keypair(t *testing.T) (*Initiator, []byte, *Request) {
	t.Helper()
	srv, _ := GenerateKey()
	cli, _ := GenerateKey()
	in, m1, err := NewInitiator(cli, srv.PublicKey(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(m1) != Msg1Size {
		t.Fatalf("msg1 size %d", len(m1))
	}
	req, err := ReadRequest(srv, m1)
	if err != nil {
		t.Fatal(err)
	}
	if !req.ClientPub.Equal(cli.PublicKey()) || req.Timestamp != 42 {
		t.Fatal("client identity or timestamp mismatch")
	}
	return in, m1, req
}

func TestHandshakeAndSession(t *testing.T) {
	in, _, req := keypair(t)
	m2, sk, err := req.Accept()
	if err != nil {
		t.Fatal(err)
	}
	ck, err := in.Finish(m2)
	if err != nil {
		t.Fatal(err)
	}
	if ck.Send != sk.Recv || ck.Recv != sk.Send || ck.Send == ck.Recv {
		t.Fatal("transport keys mismatch")
	}

	a, b := net.Pipe()
	cs, _ := NewSession(ck, a, frame.Write, frame.Read)
	ss, _ := NewSession(sk, b, frame.Write, frame.Read)
	for _, msg := range [][]byte{[]byte("hello"), bytes.Repeat([]byte{7}, 1400), {}} {
		go cs.WritePacket(msg)
		got, err := ss.ReadPacket(make([]byte, 2000))
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("roundtrip: %v", err)
		}
	}
}

func TestWrongServerKey(t *testing.T) {
	srv, _ := GenerateKey()
	other, _ := GenerateKey()
	cli, _ := GenerateKey()
	_, m1, _ := NewInitiator(cli, other.PublicKey(), 1)
	if _, err := ReadRequest(srv, m1); err == nil {
		t.Fatal("accepted message for another server")
	}
}

func TestTampered(t *testing.T) {
	srv, _ := GenerateKey()
	cli, _ := GenerateKey()
	_, m1, _ := NewInitiator(cli, srv.PublicKey(), 1)
	for i := range m1 {
		bad := append([]byte(nil), m1...)
		bad[i] ^= 1
		if _, err := ReadRequest(srv, bad); err == nil {
			t.Fatalf("accepted tampered byte %d", i)
		}
	}
}
