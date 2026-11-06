//go:build windows

// VPN-TLS для Windows: окно (WebView2) и значок в трее; туннель через Wintun,
// то же Go-ядро, что и в iOS-приложении.
package main

import (
	_ "embed"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

//go:embed ui.html
var uiHTML string

// appVersion подставляется при сборке: -ldflags "-X main.appVersion=0.2.0".
var appVersion = "dev"

func main() {
	if !windows.GetCurrentProcessToken().IsElevated() {
		relaunchAsAdmin() // на случай, если манифест не сработал
		return
	}
	if _, err := windows.CreateMutex(nil, false, utf16(`Local\VPN-TLS-app`)); err == windows.ERROR_ALREADY_EXISTS {
		// Уже запущено — показываем существующее окно.
		if h := findWindow("webview", "VPN-TLS"); h != 0 {
			bringToFront(h)
		}
		return
	}

	dir := dataDir()
	if f, err := os.OpenFile(filepath.Join(dir, "vpntls.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
		log.SetOutput(f)
	}
	log.Printf("VPN-TLS %s, данные в %s", appVersion, dir)

	settings := loadSettings(filepath.Join(dir, "settings.json"))
	c := newController(filepath.Join(dir, "profile.bin"))

	scale := dpiScale()
	width, height := uint(400*scale), uint(720*scale)
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		DataPath:  filepath.Join(dir, "webview"),
		WindowOptions: webview2.WindowOptions{
			Title: "VPN-TLS", Width: width, Height: height, Center: true, IconId: iconApp,
		},
	})
	if w == nil {
		messageBox("Не найден компонент Microsoft Edge WebView2.\nУстановите его: https://go.microsoft.com/fwlink/p/?LinkId=2124703")
		return
	}
	hwnd := windows.HWND(uintptr(w.Window()))
	w.SetSize(int(width), int(height), webview2.HintFixed)

	var quitOnce sync.Once
	quit := func() {
		quitOnce.Do(func() {
			w.Dispatch(func() {
				showWindow(hwnd, swHide)
				w.Terminate()
			})
		})
	}

	t := &tray{
		onOpen:   func() { w.Dispatch(func() { bringToFront(hwnd) }) },
		onToggle: c.toggle,
		onQuit:   quit,
		isOn:     c.isOn,
	}
	t.start()
	defer t.remove()

	c.onChange = func(status, errText string) {
		s := settings.get()
		switch status {
		case "connected":
			t.set(iconOn, "VPN-TLS — подключено")
			if s.Notify {
				t.notify("VPN-TLS", "Подключено. Весь трафик идёт через VPN.", false)
			}
		case "connecting", "reconnecting":
			t.set(iconWait, "VPN-TLS — подключение…")
			if status == "reconnecting" && s.Notify {
				t.notify("VPN-TLS", "Связь потеряна, переподключаюсь…", true)
			}
		default:
			t.set(iconOff, "VPN-TLS — отключено")
			if errText != "" && s.Notify {
				t.notify("VPN-TLS", errText, true)
			}
		}
	}

	// Крестик: свернуть в трей (если включено) вместо выхода.
	hideHint := true
	var origProc uintptr
	newProc := windows.NewCallback(func(h, m, wp, lp uintptr) uintptr {
		if m == wmClose && settings.get().CloseToTray {
			showWindow(hwnd, swHide)
			if hideHint {
				hideHint = false
				t.notify("VPN-TLS работает в фоне", "Открыть или выйти — через значок в трее.", false)
			}
			return 0
		}
		r, _, _ := procCallWindowProcW.Call(origProc, h, m, wp, lp)
		return r
	})
	gwl := gwlpWndProc
	origProc, _, _ = procSetWindowLongPtrW.Call(uintptr(hwnd), uintptr(gwl), newProc)

	w.Bind("vpnState", func() State {
		s := c.state()
		s.Settings = settings.get()
		return s
	})
	w.Bind("vpnSave", c.save)
	w.Bind("vpnRemove", c.remove)
	w.Bind("vpnToggle", c.toggle)
	w.Bind("vpnSetSettings", settings.set)
	w.Bind("vpnOpenLogs", func() { openFolder(dir) })
	w.Bind("vpnQuit", quit)
	w.SetHtml(uiHTML)

	if settings.get().AutoConnect {
		go c.connect()
	}
	w.Run()

	c.disconnect()
	w.Destroy()
}

// dataDir — папка для профиля, настроек, журнала и данных WebView2.
//
// Программа всегда работает с правами администратора, а на рабочих
// компьютерах это часто другая учётная запись (отдельный админ): её профиль
// может быть недоступен для записи. Поэтому сначала %ProgramData% (туда всегда
// могут писать администраторы), затем профиль пользователя, затем папка рядом
// с программой.
func dataDir() string {
	var candidates []string
	if pd := os.Getenv("ProgramData"); pd != "" {
		candidates = append(candidates, filepath.Join(pd, "VPN-TLS"))
	}
	if la, err := os.UserCacheDir(); err == nil {
		candidates = append(candidates, filepath.Join(la, "VPN-TLS"))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "data"))
	}
	for _, dir := range candidates {
		if writable(dir) {
			return dir
		}
	}
	return os.TempDir()
}

func writable(dir string) bool {
	if err := os.MkdirAll(filepath.Join(dir, "webview"), 0o700); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, "check-*")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

func openFolder(dir string) {
	exec.Command("explorer.exe", dir).Start()
}

func relaunchAsAdmin() {
	exe, _ := os.Executable()
	if err := windows.ShellExecute(0, utf16("runas"), utf16(exe), nil, utf16(filepath.Dir(exe)), windows.SW_NORMAL); err != nil {
		messageBox("VPN-TLS нужны права администратора, чтобы создать сетевой адаптер.")
	}
}

func messageBox(text string) {
	windows.MessageBox(0, utf16(text), utf16("VPN-TLS"), windows.MB_OK|windows.MB_ICONWARNING)
}
