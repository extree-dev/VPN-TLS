//go:build windows

// VPN-TLS для Windows: окно с кнопкой подключения (WebView2), туннель через
// Wintun, то же Go-ядро, что и в iOS-приложении.
package main

import (
	_ "embed"
	"log"
	"os"
	"path/filepath"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

//go:embed ui.html
var uiHTML string

func main() {
	if !windows.GetCurrentProcessToken().IsElevated() {
		relaunchAsAdmin() // для адаптера и маршрутов нужны права администратора
		return
	}
	name, _ := windows.UTF16PtrFromString(`Local\VPN-TLS-app`)
	if _, err := windows.CreateMutex(nil, false, name); err == windows.ERROR_ALREADY_EXISTS {
		return // уже запущено
	}

	dir := dataDir()
	if f, err := os.OpenFile(filepath.Join(dir, "vpntls.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
		log.SetOutput(f)
	}

	c := newController(filepath.Join(dir, "profile.bin"))
	defer c.disconnect()

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		DataPath:  filepath.Join(dir, "webview"),
		WindowOptions: webview2.WindowOptions{
			Title: "VPN-TLS", Width: 420, Height: 640, Center: true,
		},
	})
	if w == nil {
		messageBox("Не найден компонент Microsoft Edge WebView2.\nУстановите его: https://go.microsoft.com/fwlink/p/?LinkId=2124703")
		return
	}
	defer w.Destroy()
	w.SetSize(420, 640, webview2.HintFixed)
	w.Bind("vpnState", c.state)
	w.Bind("vpnSave", c.save)
	w.Bind("vpnRemove", c.remove)
	w.Bind("vpnToggle", c.toggle)
	w.SetHtml(uiHTML)
	w.Run()
}

// dataDir — папка для профиля, журнала и данных WebView2.
//
// Программа всегда работает с правами администратора, а на рабочих
// компьютерах это часто другая учётная запись (например, отдельный админ):
// её профиль может быть недоступен для записи. Поэтому сначала пробуем
// %ProgramData% (туда всегда могут писать администраторы), затем профиль
// пользователя, затем папку рядом с программой.
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

func relaunchAsAdmin() {
	exe, _ := os.Executable()
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err := windows.ShellExecute(0, verb, file, nil, cwd, windows.SW_NORMAL); err != nil {
		messageBox("VPN-TLS нужны права администратора, чтобы создать сетевой адаптер.")
	}
}

func messageBox(text string) {
	t, _ := windows.UTF16PtrFromString(text)
	c, _ := windows.UTF16PtrFromString("VPN-TLS")
	windows.MessageBox(0, t, c, windows.MB_OK|windows.MB_ICONWARNING)
}
