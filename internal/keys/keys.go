// Package keys хранит ключи X25519 в файлах и переводит их в base64 и обратно.
package keys

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/extree-dev/vpn-tls/internal/noise"
)

// LoadOrCreate читает приватный ключ из файла или создаёт новый (права 0600).
func LoadOrCreate(path string) (*ecdh.PrivateKey, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", path, err)
		}
		k, err := ecdh.X25519().NewPrivateKey(raw)
		return k, false, err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	k, err := noise.GenerateKey()
	if err != nil {
		return nil, false, err
	}
	enc := base64.StdEncoding.EncodeToString(k.Bytes()) + "\n"
	if err := os.WriteFile(path, []byte(enc), 0o600); err != nil {
		return nil, false, err
	}
	return k, true, nil
}

// PublicString — публичный ключ в base64.
func PublicString(k *ecdh.PrivateKey) string { return EncodePublic(k.PublicKey()) }

// EncodePublic — публичный ключ в base64.
func EncodePublic(p *ecdh.PublicKey) string {
	return base64.StdEncoding.EncodeToString(p.Bytes())
}

// ParsePublic разбирает публичный ключ из base64.
func ParsePublic(s string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("публичный ключ %q: %w", s, err)
	}
	return noise.ParsePublic(raw)
}
