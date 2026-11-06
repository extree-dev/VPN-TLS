//go:build windows

// Package winnet настраивает сеть Windows для туннеля через netsh и PowerShell.
package winnet

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // без окна консоли
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func netsh(args ...string) error {
	_, err := run("netsh", args...)
	return err
}

// Configure задаёт адаптеру адрес, MTU, DNS и низкую метрику (чтобы Windows
// предпочитала его DNS остальным).
func Configure(iface, cidr string, mtu int, dns []string) error {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return err
	}
	m := maskString(p.Bits())
	// Адаптер появляется в системе не мгновенно — несколько попыток.
	for i := 0; ; i++ {
		err = netsh("interface", "ipv4", "set", "address", "name="+iface, "source=static",
			"address="+p.Addr().String(), "mask="+m, "gateway=none")
		if err == nil || i >= 20 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	cmds := [][]string{
		{"interface", "ipv4", "set", "subinterface", iface, fmt.Sprintf("mtu=%d", mtu), "store=active"},
		{"interface", "ipv4", "set", "interface", "interface=" + iface, "metric=1"},
	}
	for i, d := range dns {
		if i == 0 {
			cmds = append(cmds, []string{"interface", "ipv4", "set", "dnsservers", "name=" + iface,
				"source=static", "address=" + d, "register=none", "validate=no"})
		} else {
			cmds = append(cmds, []string{"interface", "ipv4", "add", "dnsservers", "name=" + iface,
				"address=" + d, fmt.Sprintf("index=%d", i+1), "validate=no"})
		}
	}
	for _, c := range cmds {
		if err := netsh(c...); err != nil {
			return err
		}
	}
	run("ipconfig", "/flushdns")
	return nil
}

// RouteAll направляет весь трафик в iface, оставляя маршрут до сервера через
// текущий шлюз; IPv6 тоже заворачивается в туннель (там он отбрасывается),
// чтобы не утечь мимо VPN. Возвращает функцию отката.
func RouteAll(iface string, server netip.Addr) (func(), error) {
	out, err := run("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"$r = Find-NetRoute -RemoteIPAddress '"+server.String()+"' | Where-Object { $_.NextHop } | Select-Object -First 1; "+
			"Write-Output \"$($r.InterfaceIndex) $($r.NextHop)\"")
	if err != nil {
		return nil, err
	}
	f := strings.Fields(out)
	if len(f) != 2 {
		return nil, fmt.Errorf("не удалось определить текущий шлюз: %q", strings.TrimSpace(out))
	}
	host := server.String() + "/32"
	if err := netsh("interface", "ipv4", "add", "route", "prefix="+host, "interface="+f[0], "nexthop="+f[1], "store=active"); err != nil {
		return nil, err
	}
	undo := func() {
		netsh("interface", "ipv4", "delete", "route", "prefix="+host, "interface="+f[0], "nexthop="+f[1], "store=active")
	}
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := netsh("interface", "ipv4", "add", "route", "prefix="+half, "interface="+iface, "store=active"); err != nil {
			undo()
			return nil, err
		}
	}
	for _, half := range []string{"::/1", "8000::/1"} {
		netsh("interface", "ipv6", "add", "route", "prefix="+half, "interface="+iface, "store=active") // без IPv6 в системе — не страшно
	}
	return undo, nil
}

func maskString(bits int) string {
	m := uint32(0)
	if bits > 0 {
		m = ^uint32(0) << (32 - bits)
	}
	return fmt.Sprintf("%d.%d.%d.%d", m>>24, m>>16&0xff, m>>8&0xff, m&0xff)
}
