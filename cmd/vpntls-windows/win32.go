//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32  = windows.NewLazySystemDLL("user32.dll")
	shell32 = windows.NewLazySystemDLL("shell32.dll")

	procRegisterClassExW       = user32.NewProc("RegisterClassExW")
	procCreateWindowExW        = user32.NewProc("CreateWindowExW")
	procDefWindowProcW         = user32.NewProc("DefWindowProcW")
	procGetMessageW            = user32.NewProc("GetMessageW")
	procTranslateMessage       = user32.NewProc("TranslateMessage")
	procDispatchMessageW       = user32.NewProc("DispatchMessageW")
	procPostMessageW           = user32.NewProc("PostMessageW")
	procLoadImageW             = user32.NewProc("LoadImageW")
	procCreatePopupMenu        = user32.NewProc("CreatePopupMenu")
	procAppendMenuW            = user32.NewProc("AppendMenuW")
	procTrackPopupMenu         = user32.NewProc("TrackPopupMenu")
	procDestroyMenu            = user32.NewProc("DestroyMenu")
	procGetCursorPos           = user32.NewProc("GetCursorPos")
	procSetForegroundWindow    = user32.NewProc("SetForegroundWindow")
	procShowWindow             = user32.NewProc("ShowWindow")
	procIsWindowVisible        = user32.NewProc("IsWindowVisible")
	procIsIconic               = user32.NewProc("IsIconic")
	procSetWindowLongPtrW      = user32.NewProc("SetWindowLongPtrW")
	procCallWindowProcW        = user32.NewProc("CallWindowProcW")
	procRegisterWindowMessageW = user32.NewProc("RegisterWindowMessageW")
	procGetDpiForSystem        = user32.NewProc("GetDpiForSystem")
	procGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	procSetWindowPos           = user32.NewProc("SetWindowPos")
	procShellNotifyIconW       = shell32.NewProc("Shell_NotifyIconW")
	procFindWindowW            = user32.NewProc("FindWindowW")
)

const (
	wmClose       = 0x0010
	wmCommand     = 0x0111
	wmNull        = 0x0000
	wmApp         = 0x8000
	wmLButtonUp   = 0x0202
	wmLButtonDbl  = 0x0203
	wmRButtonUp   = 0x0205
	wmContextMenu = 0x007B

	swHide    = 0
	swShow    = 5
	swRestore = 9

	imageIcon     = 1
	lrDefaultSize = 0x0040
	lrShared      = 0x8000

	smCxSmIcon = 49
	smCySmIcon = 50

	mfString    = 0x0000
	mfSeparator = 0x0800
	mfGrayed    = 0x0001
	mfChecked   = 0x0008

	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100
	tpmBottomAlign = 0x0020

	nimAdd     = 0
	nimModify  = 1
	nimDelete  = 2
	nimVersion = 4
	nifMessage = 0x01
	nifIcon    = 0x02
	nifTip     = 0x04
	nifInfo    = 0x10
	nifShowTip = 0x80
	niifInfo   = 0x01
	niifWarn   = 0x02

	gwlpWndProc = -4
)

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type msg struct {
	Hwnd    windows.HWND
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	private uint32
}

type point struct{ X, Y int32 }

// notifyIconData — NOTIFYICONDATAW (версия для Vista+).
type notifyIconData struct {
	Size            uint32
	Wnd             windows.HWND
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            windows.Handle
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUIDItem        windows.GUID
	BalloonIcon     windows.Handle
}

func utf16(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }

func copyUTF16(dst []uint16, s string) {
	u, _ := windows.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}

// loadIcon загружает иконку из ресурсов программы (см. tools/winres).
func loadIcon(id int, small bool) windows.Handle {
	var inst windows.Handle
	windows.GetModuleHandleEx(0, nil, &inst)
	cx, cy := uintptr(0), uintptr(0)
	flags := uintptr(lrDefaultSize | lrShared)
	if small {
		x, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
		y, _, _ := procGetSystemMetrics.Call(smCySmIcon)
		cx, cy, flags = x, y, lrShared
	}
	h, _, _ := procLoadImageW.Call(uintptr(inst), uintptr(id), imageIcon, cx, cy, flags)
	return windows.Handle(h)
}

// dpiScale — масштаб экрана (1.0 = 100 %, 1.5 = 150 %).
func dpiScale() float64 {
	if procGetDpiForSystem.Find() != nil {
		return 1
	}
	d, _, _ := procGetDpiForSystem.Call()
	if d == 0 {
		return 1
	}
	return float64(d) / 96
}

func showWindow(h windows.HWND, cmd int) { procShowWindow.Call(uintptr(h), uintptr(cmd)) }

func bringToFront(h windows.HWND) {
	if r, _, _ := procIsIconic.Call(uintptr(h)); r != 0 {
		showWindow(h, swRestore)
	} else {
		showWindow(h, swShow)
	}
	procSetForegroundWindow.Call(uintptr(h))
}

func isVisible(h windows.HWND) bool {
	r, _, _ := procIsWindowVisible.Call(uintptr(h))
	return r != 0
}

func findWindow(class, title string) windows.HWND {
	h, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(utf16(class))), uintptr(unsafe.Pointer(utf16(title))))
	return windows.HWND(h)
}
