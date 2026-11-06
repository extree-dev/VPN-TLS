//go:build windows

package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Строка подключения содержит ключ клиента, поэтому на диске она хранится
// зашифрованной DPAPI: расшифровать её может только этот пользователь Windows.

func saveProfile(path, link string) error {
	enc, err := dpapi([]byte(link), true)
	if err != nil {
		return err
	}
	return os.WriteFile(path, enc, 0o600)
}

func loadProfile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	dec, err := dpapi(data, false)
	return string(dec), err
}

func dpapi(in []byte, encrypt bool) ([]byte, error) {
	if len(in) == 0 {
		return nil, os.ErrInvalid
	}
	src := windows.DataBlob{Size: uint32(len(in)), Data: &in[0]}
	var dst windows.DataBlob
	var err error
	if encrypt {
		err = windows.CryptProtectData(&src, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &dst)
	} else {
		err = windows.CryptUnprotectData(&src, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &dst)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(dst.Data)))
	return append([]byte(nil), unsafe.Slice(dst.Data, dst.Size)...), nil
}
