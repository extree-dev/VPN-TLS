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

// PacketConn — источник и приёмник целых пакетов (например, шифрованная сессия).
type PacketConn interface {
	ReadPacket(buf []byte) ([]byte, error)
	WritePacket(p []byte) error
}

// Pipe гоняет пакеты между TUN и PacketConn в обе стороны, пока одна из сторон не закроется.
func Pipe(tun io.ReadWriter, conn PacketConn) error {
	errc := make(chan error, 2)
	go func() { // TUN -> сеть
		buf := make([]byte, MaxSize)
		for {
			n, err := tun.Read(buf)
			if err != nil {
				errc <- err
				return
			}
			if err := conn.WritePacket(buf[:n]); err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() { // сеть -> TUN
		buf := make([]byte, MaxSize)
		for {
			p, err := conn.ReadPacket(buf)
			if err != nil {
				errc <- err
				return
			}
			if _, err := tun.Write(p); err != nil {
				errc <- err
				return
			}
		}
	}()
	return <-errc
}
