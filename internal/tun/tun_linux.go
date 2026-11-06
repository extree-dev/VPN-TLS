//go:build linux

// Package tun открывает TUN-интерфейс на Linux без внешних зависимостей.
package tun

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const (
	iffTun    = 0x0001
	iffNoPi   = 0x1000
	tunSetIff = 0x400454ca
)

type ifReq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

// Device — открытый TUN-интерфейс. Read/Write работают с «голыми» IP-пакетами.
type Device struct {
	*os.File
	Name string
}

// Open создаёт (или открывает) TUN-интерфейс с указанным именем.
func Open(name string) (*Device, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	var req ifReq
	copy(req.Name[:], name)
	req.Flags = iffTun | iffNoPi
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetIff, uintptr(unsafe.Pointer(&req))); e != 0 {
		f.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF: %w", e)
	}
	return &Device{File: f, Name: strings.TrimRight(string(req.Name[:]), "\x00")}, nil
}

// Up назначает адрес (CIDR, например 10.8.0.1/24), MTU и поднимает интерфейс.
func (d *Device) Up(cidr string, mtu int) error {
	cmds := [][]string{
		{"ip", "addr", "add", cidr, "dev", d.Name},
		{"ip", "link", "set", "dev", d.Name, "mtu", fmt.Sprint(mtu), "up"},
	}
	for _, c := range cmds {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", strings.Join(c, " "), err, out)
		}
	}
	return nil
}
