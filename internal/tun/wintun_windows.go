//go:build windows

// TUN на Windows через драйвер Wintun (https://www.wintun.net, авторы WireGuard).
// wintun.dll должна лежать рядом с программой.
package tun

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintun                   *windows.LazyDLL
	procOpenAdapter          *windows.LazyProc
	procCreateAdapter        *windows.LazyProc
	procCloseAdapter         *windows.LazyProc
	procStartSession         *windows.LazyProc
	procEndSession           *windows.LazyProc
	procGetReadWaitEvent     *windows.LazyProc
	procReceivePacket        *windows.LazyProc
	procReleaseReceivePacket *windows.LazyProc
	procAllocateSendPacket   *windows.LazyProc
	procSendPacket           *windows.LazyProc
)

func loadWintun() error {
	if wintun != nil {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Полный путь: DLL грузится только из папки программы, не из случайных мест.
	dll := windows.NewLazyDLL(filepath.Join(filepath.Dir(exe), "wintun.dll"))
	if err := dll.Load(); err != nil {
		return errors.New("не найден wintun.dll рядом с программой")
	}
	wintun = dll
	procOpenAdapter = dll.NewProc("WintunOpenAdapter")
	procCreateAdapter = dll.NewProc("WintunCreateAdapter")
	procCloseAdapter = dll.NewProc("WintunCloseAdapter")
	procStartSession = dll.NewProc("WintunStartSession")
	procEndSession = dll.NewProc("WintunEndSession")
	procGetReadWaitEvent = dll.NewProc("WintunGetReadWaitEvent")
	procReceivePacket = dll.NewProc("WintunReceivePacket")
	procReleaseReceivePacket = dll.NewProc("WintunReleaseReceivePacket")
	procAllocateSendPacket = dll.NewProc("WintunAllocateSendPacket")
	procSendPacket = dll.NewProc("WintunSendPacket")
	return nil
}

// Постоянный GUID: при каждом запуске Windows видит тот же адаптер, а не плодит новые.
var adapterGUID = windows.GUID{Data1: 0x7670746c, Data2: 0x7300, Data3: 0x4e54, Data4: [8]byte{0x56, 0x50, 0x4e, 0x2d, 0x54, 0x4c, 0x53, 0x01}}

// Device — адаптер Wintun. Read/Write работают с «голыми» IP-пакетами.
type Device struct {
	Name    string
	adapter uintptr
	session uintptr
	readEv  windows.Handle
	closeEv windows.Handle

	mu     sync.RWMutex
	closed bool
}

// Open создаёт (или открывает существующий) адаптер с именем name.
func Open(name string) (*Device, error) {
	if err := loadWintun(); err != nil {
		return nil, err
	}
	n, _ := windows.UTF16PtrFromString(name)
	typ, _ := windows.UTF16PtrFromString("VPN-TLS")
	a, _, _ := procOpenAdapter.Call(uintptr(unsafe.Pointer(n)))
	if a == 0 {
		var err error
		a, _, err = procCreateAdapter.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(typ)), uintptr(unsafe.Pointer(&adapterGUID)))
		if a == 0 {
			return nil, errors.New("не удалось создать адаптер Wintun: " + err.Error())
		}
	}
	s, _, err := procStartSession.Call(a, 0x800000) // кольцевой буфер 8 МБ
	if s == 0 {
		procCloseAdapter.Call(a)
		return nil, errors.New("не удалось запустить сессию Wintun: " + err.Error())
	}
	ev, _, _ := procGetReadWaitEvent.Call(s)
	closeEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		procEndSession.Call(s)
		procCloseAdapter.Call(a)
		return nil, err
	}
	return &Device{Name: name, adapter: a, session: s, readEv: windows.Handle(ev), closeEv: closeEv}, nil
}

// Read читает один пакет (блокируется, пока пакета нет).
func (d *Device) Read(buf []byte) (int, error) {
	for {
		d.mu.RLock()
		if d.closed {
			d.mu.RUnlock()
			return 0, os.ErrClosed
		}
		var size uint32
		p, _, err := procReceivePacket.Call(d.session, uintptr(unsafe.Pointer(&size)))
		if p != 0 {
			n := copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(p)), size))
			procReleaseReceivePacket.Call(d.session, p)
			d.mu.RUnlock()
			return n, nil
		}
		d.mu.RUnlock()
		switch err {
		case windows.ERROR_NO_MORE_ITEMS:
			windows.WaitForMultipleObjects([]windows.Handle{d.readEv, d.closeEv}, false, windows.INFINITE)
		case windows.ERROR_HANDLE_EOF:
			return 0, os.ErrClosed
		default:
			return 0, err
		}
	}
}

// Write отправляет пакет в систему. Если буфер переполнен, пакет теряется.
func (d *Device) Write(p []byte) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return 0, os.ErrClosed
	}
	b, _, _ := procAllocateSendPacket.Call(d.session, uintptr(len(p)))
	if b == 0 {
		return len(p), nil
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(b)), len(p)), p)
	procSendPacket.Call(d.session, b)
	return len(p), nil
}

// Close закрывает сессию и удаляет адаптер (вместе с его адресами и маршрутами).
func (d *Device) Close() error {
	windows.SetEvent(d.closeEv)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	procEndSession.Call(d.session)
	procCloseAdapter.Call(d.adapter)
	windows.CloseHandle(d.closeEv)
	return nil
}
