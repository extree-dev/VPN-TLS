package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sort"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/extree-dev/vpn-tls/internal/clients"
	"github.com/extree-dev/vpn-tls/internal/config"
	"github.com/extree-dev/vpn-tls/internal/keys"
	"github.com/extree-dev/vpn-tls/internal/noise"
	"github.com/extree-dev/vpn-tls/internal/transport"
)

func clientCmd(o *options, args []string) {
	log.SetFlags(0)
	if len(args) == 0 {
		usage()
	}
	switch args[0] {
	case "add":
		if len(args) != 2 {
			usage()
		}
		clientAdd(o, args[1])
	case "list":
		clientList(o)
	case "remove", "rm":
		if len(args) != 2 {
			usage()
		}
		n, err := clients.Remove(o.clientsFile, args[1])
		if err != nil {
			log.Fatal(err)
		}
		if n == 0 {
			log.Fatalf("клиент %q не найден", args[1])
		}
		fmt.Printf("клиент %q удалён; если он был подключён, сервер отключит его в течение нескольких секунд\n", args[1])
	default:
		usage()
	}
}

func usage() {
	log.Fatal(`использование:
  vpn-server client add <имя>
  vpn-server client list
  vpn-server client remove <имя>`)
}

func clientAdd(o *options, name string) {
	data, _ := os.ReadFile(o.clientsFile)
	existing := clients.Parse(string(data))
	for _, e := range existing {
		if e.Name == name {
			log.Fatalf("клиент %q уже есть; удалите его (client remove) или выберите другое имя", name)
		}
	}

	gw, err := netip.ParsePrefix(o.addr)
	if err != nil {
		log.Fatal(err)
	}
	used := map[netip.Addr]bool{gw.Addr(): true}
	for _, e := range existing {
		used[e.IP] = true
	}
	var ip netip.Addr
	p := gw.Masked()
	for a := p.Addr().Next(); p.Contains(a.Next()); a = a.Next() {
		if !used[a] {
			ip = a
			break
		}
	}
	if !ip.IsValid() {
		log.Fatal("в подсети туннеля нет свободных адресов")
	}

	ck, err := noise.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	e := clients.Entry{Key: keys.PublicString(ck), IP: ip, Name: name}
	if err := clients.Append(o.clientsFile, e); err != nil {
		log.Fatal(err)
	}

	server := loadKey(o.keyFile)
	public := o.public
	if public == "" {
		public = net.JoinHostPort(o.domain, env("public-port", "443"))
	}
	pin := ""
	switch o.pin {
	case "off", "":
	case "auto":
		pin = certPin(o.certFile)
	default:
		pin = o.pin
	}
	link := &config.Link{
		ClientKey: ck, ServerPub: server.PublicKey(), Addr: public,
		Path: o.path, SNI: o.domain, Pin: pin, Name: name,
	}
	s := link.String()
	fmt.Printf("клиент %q добавлен, адрес в туннеле %s\n\n", name, ip)
	if q, err := qrcode.New(s, qrcode.Low); err == nil {
		fmt.Println(q.ToSmallString(false))
	}
	fmt.Printf("строка подключения (это секрет — в ней ключ клиента):\n\n%s\n\n", s)
	fmt.Printf("подключение с Linux:  sudo ./client -connect '%s' -route-all\n", s)
}

func clientList(o *options) {
	data, err := os.ReadFile(o.clientsFile)
	if err != nil {
		log.Fatal(err)
	}
	es := clients.Parse(string(data))
	sort.Slice(es, func(i, j int) bool { return es[i].IP.Less(es[j].IP) })
	if len(es) == 0 {
		fmt.Println("клиентов нет")
		return
	}
	fmt.Printf("%-16s %-16s %s\n", "ИМЯ", "АДРЕС", "КЛЮЧ")
	for _, e := range es {
		ip := "авто"
		if e.IP.IsValid() {
			ip = e.IP.String()
		}
		name := e.Name
		if name == "" {
			name = "-"
		}
		fmt.Printf("%-16s %-16s %s\n", name, ip, e.Key)
	}
}

func certPin(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("сертификат %s: %v (запустите сервер хотя бы раз или задайте -pin off)", path, err)
	}
	b, _ := pem.Decode(data)
	if b == nil {
		log.Fatalf("сертификат %s: не PEM", path)
	}
	if _, err := x509.ParseCertificate(b.Bytes); err != nil {
		log.Fatal(err)
	}
	return transport.Fingerprint(b.Bytes)
}
