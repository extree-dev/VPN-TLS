// Генерирует ресурсы Windows для VPN-TLS (иконки, манифест, сведения о версии)
// в виде .syso — Go подхватывает их при сборке автоматически.
//
//	cd tools/winres && go run . -version 0.2.0
package main

import (
	"flag"
	"fmt"
	"image"
	"image/png"
	"log"
	"os"
	"path/filepath"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

// ID иконок: 1 — приложения (Проводник берёт первую), 2–4 — для трея.
const (
	iconApp  = 1
	iconOn   = 2
	iconOff  = 3
	iconWait = 4
)

func main() {
	ver := flag.String("version", "0.2.0", "версия приложения")
	assets := flag.String("assets", "../../assets/icon", "папка с PNG")
	out := flag.String("out", "../../cmd/vpntls-windows", "куда положить .syso")
	flag.Parse()

	rs := &winres.ResourceSet{}
	appSizes := []int{16, 20, 24, 32, 40, 48, 64, 96, 128, 256}
	traySizes := []int{16, 20, 24, 32, 40, 48, 64}
	for id, set := range map[int]struct {
		name  string
		sizes []int
	}{
		iconApp: {"app", appSizes}, iconOn: {"tray-on", traySizes},
		iconOff: {"tray-off", traySizes}, iconWait: {"tray-wait", traySizes},
	} {
		var imgs []image.Image
		for _, s := range set.sizes {
			imgs = append(imgs, load(filepath.Join(*assets, fmt.Sprintf("%s-%d.png", set.name, s))))
		}
		ico, err := winres.NewIconFromImages(imgs)
		if err != nil {
			log.Fatal(err)
		}
		if err := rs.SetIcon(winres.ID(id), ico); err != nil {
			log.Fatal(err)
		}
	}

	rs.SetManifest(winres.AppManifest{
		Description:         "VPN-TLS",
		Compatibility:       winres.Win10AndAbove,
		ExecutionLevel:      winres.RequireAdministrator, // адаптер и маршруты — только с правами администратора
		DPIAwareness:        winres.DPIPerMonitorV2,      // чёткое окно на экранах с масштабированием
		UseCommonControlsV6: true,
	})

	var vi version.Info
	vi.SetFileVersion(*ver)
	vi.SetProductVersion(*ver)
	for k, v := range map[string]string{
		version.ProductName:      "VPN-TLS",
		version.FileDescription:  "VPN-TLS",
		version.CompanyName:      "extree",
		version.LegalCopyright:   "© 2026 extree",
		version.OriginalFilename: "VPN-TLS.exe",
		version.InternalName:     "vpntls",
	} {
		vi.Set(0, k, v)
	}
	rs.SetVersionInfo(vi)

	for arch, name := range map[winres.Arch]string{winres.ArchAMD64: "amd64", winres.ArchARM64: "arm64"} {
		f, err := os.Create(filepath.Join(*out, "rsrc_windows_"+name+".syso"))
		if err != nil {
			log.Fatal(err)
		}
		if err := rs.WriteObject(f, arch); err != nil {
			log.Fatal(err)
		}
		f.Close()
	}
	log.Printf("готово: ресурсы версии %s", *ver)
}

func load(path string) image.Image {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		log.Fatalf("%s: %v", path, err)
	}
	return img
}
