// Package frame — кадрирование пакетов в потоке: [2 байта длины][данные].
// Шифрование — в пакете noise, маскировка под HTTPS — на следующем этапе.
package frame

import (
	"encoding/binary"
	"errors"
	"io"
)

const MaxSize = 65535

// Write отправляет один пакет в поток.
func Write(w io.Writer, p []byte) error {
	if len(p) > MaxSize {
		return errors.New("frame: packet too large")
	}
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf, uint16(len(p)))
	copy(buf[2:], p)
	_, err := w.Write(buf)
	return err
}

// Read читает один пакет из потока в buf и возвращает его.
func Read(r io.Reader, buf []byte) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n > len(buf) {
		return nil, errors.New("frame: buffer too small")
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}
