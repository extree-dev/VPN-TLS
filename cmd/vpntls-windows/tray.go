//go:build windows

package main

import (
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Иконки в ресурсах (tools/winres): 2 — подключено, 3 — отключено, 4 — подключение.
const (
	iconApp  = 1
	iconOn   = 2
	iconOff  = 3
	iconWait = 4
)

const (
	cmdOpen = 100 + iota
	cmdToggle
	cmdQuit
)

const trayCallback = wmApp + 1

// tray — значок в области уведомлений со своим окном-получателем сообщений
// и своим потоком (у окна WebView2 свой цикл сообщений).
type tray struct {
	onOpen, onToggle, onQuit func()
	isOn                     func() bool

	mu      sync.Mutex
	hwnd    windows.HWND
	nid     notifyIconData
	created uint32 // сообщение TaskbarCreated — Проводник перезапущен, значок надо вернуть
	ready   chan struct{}
}

func (t *tray) start() {
	t.ready = make(chan struct{})
	go t.loop()
	<-t.ready
}

func (t *tray) loop() {
	runtime.LockOSThread()
	var inst windows.Handle
	windows.GetModuleHandleEx(0, nil, &inst)
	cls := utf16("VPN-TLS-tray")
	wc := wndClassEx{Instance: inst, ClassName: cls, WndProc: windows.NewCallback(t.wndProc)}
	wc.Size = uint32(unsafe.Sizeof(wc))
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	h, _, _ := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(utf16("VPN-TLS"))),
		0, 0, 0, 0, 0, 0, 0, uintptr(inst), 0)
	t.hwnd = windows.HWND(h)
	c, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(utf16("TaskbarCreated"))))
	t.created = uint32(c)

	t.nid = notifyIconData{Wnd: t.hwnd, ID: 1, Flags: nifMessage | nifIcon | nifTip | nifShowTip,
		CallbackMessage: trayCallback, Icon: loadIcon(iconOff, true)}
	t.nid.Size = uint32(unsafe.Sizeof(t.nid))
	copyUTF16(t.nid.Tip[:], "VPN-TLS — отключено")
	t.add()
	close(t.ready)

	var m msg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (t *tray) add() {
	procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&t.nid)))
	t.nid.Version = 4 // NOTIFYICON_VERSION_4
	procShellNotifyIconW.Call(nimVersion, uintptr(unsafe.Pointer(&t.nid)))
}

func (t *tray) wndProc(hwnd, m, wp, lp uintptr) uintptr {
	switch {
	case m == trayCallback:
		switch uint32(lp) & 0xffff {
		case wmLButtonUp, wmLButtonDbl:
			t.onOpen()
		case wmRButtonUp, wmContextMenu:
			t.menu()
		}
		return 0
	case t.created != 0 && uint32(m) == t.created:
		t.mu.Lock()
		t.add()
		t.mu.Unlock()
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, m, wp, lp)
	return r
}

func (t *tray) menu() {
	menu, _, _ := procCreatePopupMenu.Call()
	defer procDestroyMenu.Call(menu)
	add := func(flags uintptr, id int, text string) {
		procAppendMenuW.Call(menu, flags, uintptr(id), uintptr(unsafe.Pointer(utf16(text))))
	}
	add(mfString, cmdOpen, "Открыть VPN-TLS")
	if t.isOn() {
		add(mfString, cmdToggle, "Отключить")
	} else {
		add(mfString, cmdToggle, "Подключить")
	}
	add(mfSeparator, 0, "")
	add(mfString, cmdQuit, "Выход")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(uintptr(t.hwnd)) // иначе меню не закроется по клику мимо
	cmd, _, _ := procTrackPopupMenu.Call(menu, tpmRightButton|tpmReturnCmd|tpmBottomAlign,
		uintptr(pt.X), uintptr(pt.Y), 0, uintptr(t.hwnd), 0)
	procPostMessageW.Call(uintptr(t.hwnd), wmNull, 0, 0)
	switch int(cmd) {
	case cmdOpen:
		t.onOpen()
	case cmdToggle:
		t.onToggle()
	case cmdQuit:
		t.onQuit()
	}
}

// set меняет значок и подсказку.
func (t *tray) set(icon int, tip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nid.Flags = nifIcon | nifTip | nifShowTip
	t.nid.Icon = loadIcon(icon, true)
	copyUTF16(t.nid.Tip[:], tip)
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&t.nid)))
}

// notify показывает уведомление Windows от имени значка.
func (t *tray) notify(title, text string, warn bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.nid
	n.Flags = nifInfo
	copyUTF16(n.InfoTitle[:], title)
	copyUTF16(n.Info[:], text)
	n.InfoFlags = niifInfo
	if warn {
		n.InfoFlags = niifWarn
	}
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&n)))
}

func (t *tray) remove() {
	t.mu.Lock()
	defer t.mu.Unlock()
	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&t.nid)))
}
