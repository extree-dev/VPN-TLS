//go:build linux

// Package route настраивает маршруты и NAT на Linux через ip и iptables.
package route

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func run(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnableNAT выпускает подсеть туннеля в интернет через интерфейс по умолчанию
// (MASQUERADE) и разрешает форвардинг. Возвращает функцию отката.
func EnableNAT(subnet string) (func(), error) {
	iface, err := defaultIface()
	if err != nil {
		return nil, err
	}
	rules := [][]string{
		{"-t", "nat", "POSTROUTING", "-s", subnet, "-o", iface, "-j", "MASQUERADE"},
		{"-t", "filter", "FORWARD", "-s", subnet, "-j", "ACCEPT"},
		{"-t", "filter", "FORWARD", "-d", subnet, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	var added [][]string
	undo := func() {
		for i := len(added) - 1; i >= 0; i-- {
			r := added[i]
			run(append([]string{"iptables", r[0], r[1], "-D", r[2]}, r[3:]...)...)
		}
	}
	for _, r := range rules {
		args := append([]string{"iptables", r[0], r[1], "-I", r[2]}, r[3:]...)
		if err := run(args...); err != nil {
			undo()
			return nil, err
		}
		added = append(added, r)
	}
	return undo, nil
}

// RouteAll направляет весь трафик через dev, оставляя маршрут до самого
// сервера через текущий шлюз. Возвращает функцию отката.
func RouteAll(dev string, server net.IP) (func(), error) {
	out, err := exec.Command("ip", "route", "get", server.String()).Output()
	if err != nil {
		return nil, fmt.Errorf("ip route get %s: %w", server, err)
	}
	f := strings.Fields(string(out))
	hostRoute := []string{"ip", "route", "replace", server.String() + "/32"}
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "via" || f[i] == "dev" {
			hostRoute = append(hostRoute, f[i], f[i+1])
		}
	}
	if err := run(hostRoute...); err != nil {
		return nil, err
	}
	// Две половины /1 перекрывают маршрут по умолчанию, не удаляя его.
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("ip", "route", "replace", half, "dev", dev); err != nil {
			run("ip", "route", "del", server.String()+"/32")
			return nil, err
		}
	}
	// Туннель только IPv4: чтобы IPv6-трафик не ушёл мимо VPN, закрываем его
	// маршрутами unreachable — приложения сразу переключатся на IPv4.
	// Если IPv6 в системе выключен, команды просто не сработают — это нормально.
	v6 := 0
	for _, half := range []string{"::/1", "8000::/1"} {
		if run("ip", "-6", "route", "replace", "unreachable", half) == nil {
			v6++
		}
	}
	return func() {
		run("ip", "route", "del", "0.0.0.0/1", "dev", dev)
		run("ip", "route", "del", "128.0.0.0/1", "dev", dev)
		run("ip", "route", "del", server.String()+"/32")
		if v6 > 0 {
			run("ip", "-6", "route", "del", "unreachable", "::/1")
			run("ip", "-6", "route", "del", "unreachable", "8000::/1")
		}
	}, nil
}

const resolvConf = "/etc/resolv.conf"

// SetDNS записывает DNS-серверы туннеля в /etc/resolv.conf и возвращает
// функцию, которая вернёт прежний файл (или символическую ссылку).
func SetDNS(servers []string) (func(), error) {
	if len(servers) == 0 {
		return func() {}, nil
	}
	link, linkErr := os.Readlink(resolvConf)
	old, err := os.ReadFile(resolvConf)
	if err != nil && linkErr != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("# записано vpn-tls, будет восстановлено при отключении\n")
	for _, s := range servers {
		b.WriteString("nameserver " + s + "\n")
	}
	tmp := resolvConf + ".vpntls"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, resolvConf); err != nil {
		return nil, err
	}
	return func() {
		if linkErr == nil {
			os.Remove(resolvConf)
			os.Symlink(link, resolvConf)
			return
		}
		os.WriteFile(resolvConf, old, 0o644)
	}, nil
}

func defaultIface() (string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1], nil
		}
	}
	return "", fmt.Errorf("не найден маршрут по умолчанию")
}
