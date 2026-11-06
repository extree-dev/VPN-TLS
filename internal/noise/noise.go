// Package noise реализует рукопожатие по схеме Noise IK
// (Noise_IK_25519_AESGCM_SHA256, https://noiseprotocol.org/noise.html)
// и шифрованный транспорт поверх него. Только стандартная библиотека Go.
//
// IK: клиент заранее знает публичный ключ сервера, сервер узнаёт ключ
// клиента из первого сообщения и проверяет его по списку разрешённых.
//
//	-> e, es, s, ss   (+ payload: метка времени против повторов)
//	<- e, ee, se
package noise

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	mrand "math/rand/v2"
)

const (
	protocolName = "Noise_IK_25519_AESGCM_SHA256"
	prologue     = "vpn-tls/1"
	keySize      = 32
	tagSize      = 16

	// Msg1Size — размер первого сообщения: e(32) + s(32+16) + payload(8+16).
	Msg1Size = keySize + keySize + tagSize + 8 + tagSize
	// Msg2Size — размер второго сообщения: e(32) + пустой payload(16).
	Msg2Size = keySize + tagSize
)

var (
	ErrHandshake = errors.New("noise: handshake failed")
	ErrNonce     = errors.New("noise: nonce exhausted")
)

var curve = ecdh.X25519()

// GenerateKey создаёт новый ключ X25519.
func GenerateKey() (*ecdh.PrivateKey, error) { return curve.GenerateKey(rand.Reader) }

// ParsePublic разбирает 32-байтовый публичный ключ X25519.
func ParsePublic(b []byte) (*ecdh.PublicKey, error) { return curve.NewPublicKey(b) }

// ---------- symmetric state ----------

type symmetric struct {
	ck, h [32]byte
	k     cipher.AEAD
	n     uint64
}

func newSymmetric() *symmetric {
	s := &symmetric{}
	copy(s.h[:], protocolName) // имя короче 32 байт — дополняется нулями
	s.ck = s.h
	s.mixHash([]byte(prologue))
	return s
}

func (s *symmetric) mixHash(data []byte) {
	h := sha256.New()
	h.Write(s.h[:])
	h.Write(data)
	h.Sum(s.h[:0])
}

func (s *symmetric) mixKey(ikm []byte) error {
	ck, k := hkdf2(s.ck[:], ikm)
	s.ck = ck
	aead, err := newAEAD(k[:])
	if err != nil {
		return err
	}
	s.k, s.n = aead, 0
	return nil
}

func (s *symmetric) encryptAndHash(pt []byte) []byte {
	ct := s.k.Seal(nil, nonce(s.n), pt, s.h[:])
	s.n++
	s.mixHash(ct)
	return ct
}

func (s *symmetric) decryptAndHash(ct []byte) ([]byte, error) {
	pt, err := s.k.Open(nil, nonce(s.n), ct, s.h[:])
	if err != nil {
		return nil, ErrHandshake
	}
	s.n++
	s.mixHash(ct)
	return pt, nil
}

func (s *symmetric) split() (k1, k2 [32]byte) { return hkdf2(s.ck[:], nil) }

func hmacSHA256(key []byte, data ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

// hkdf2 — HKDF из спецификации Noise с двумя выходами.
func hkdf2(ck, ikm []byte) (out1, out2 [32]byte) {
	tmp := hmacSHA256(ck, ikm)
	o1 := hmacSHA256(tmp, []byte{1})
	o2 := hmacSHA256(tmp, o1, []byte{2})
	copy(out1[:], o1)
	copy(out2[:], o2)
	return
}

func newAEAD(k []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// nonce в формате Noise для AES-GCM: 4 нулевых байта + 8 байт счётчика (big-endian).
func nonce(n uint64) []byte {
	var b [12]byte
	binary.BigEndian.PutUint64(b[4:], n)
	return b[:]
}

func dh(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	out, err := priv.ECDH(pub)
	if err != nil {
		return nil, ErrHandshake
	}
	return out, nil
}

// ---------- initiator (клиент) ----------

// Initiator хранит состояние клиента между двумя сообщениями рукопожатия.
type Initiator struct {
	sym *symmetric
	s   *ecdh.PrivateKey
	e   *ecdh.PrivateKey
}

// NewInitiator готовит первое сообщение. timestamp — монотонная метка (unix-нс),
// сервер отвергает сообщения с меткой не больше предыдущей для этого клиента.
func NewInitiator(static *ecdh.PrivateKey, serverPub *ecdh.PublicKey, timestamp uint64) (*Initiator, []byte, error) {
	sym := newSymmetric()
	sym.mixHash(serverPub.Bytes())

	e, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	msg := append([]byte(nil), e.PublicKey().Bytes()...)
	sym.mixHash(e.PublicKey().Bytes())

	k, err := dh(e, serverPub) // es
	if err != nil {
		return nil, nil, err
	}
	if err := sym.mixKey(k); err != nil {
		return nil, nil, err
	}
	msg = append(msg, sym.encryptAndHash(static.PublicKey().Bytes())...) // s

	if k, err = dh(static, serverPub); err != nil { // ss
		return nil, nil, err
	}
	if err := sym.mixKey(k); err != nil {
		return nil, nil, err
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], timestamp)
	msg = append(msg, sym.encryptAndHash(ts[:])...)

	return &Initiator{sym: sym, s: static, e: e}, msg, nil
}

// Finish обрабатывает ответ сервера и возвращает ключи транспорта.
func (in *Initiator) Finish(msg2 []byte) (*Keys, error) {
	if len(msg2) != Msg2Size {
		return nil, ErrHandshake
	}
	re, err := ParsePublic(msg2[:keySize])
	if err != nil {
		return nil, ErrHandshake
	}
	in.sym.mixHash(msg2[:keySize])
	for _, priv := range []*ecdh.PrivateKey{in.e, in.s} { // ee, se
		k, err := dh(priv, re)
		if err != nil {
			return nil, err
		}
		if err := in.sym.mixKey(k); err != nil {
			return nil, err
		}
	}
	if _, err := in.sym.decryptAndHash(msg2[keySize:]); err != nil {
		return nil, err
	}
	k1, k2 := in.sym.split()
	return &Keys{Send: k1, Recv: k2}, nil
}

// ---------- responder (сервер) ----------

// Request — разобранное первое сообщение клиента.
type Request struct {
	ClientPub *ecdh.PublicKey
	Timestamp uint64

	sym *symmetric
	re  *ecdh.PublicKey
}

// ReadRequest расшифровывает первое сообщение. Любая ошибка — ErrHandshake,
// без подробностей, чтобы не давать подсказок тому, кто прощупывает сервер.
func ReadRequest(static *ecdh.PrivateKey, msg []byte) (*Request, error) {
	if len(msg) != Msg1Size {
		return nil, ErrHandshake
	}
	sym := newSymmetric()
	sym.mixHash(static.PublicKey().Bytes())

	re, err := ParsePublic(msg[:keySize])
	if err != nil {
		return nil, ErrHandshake
	}
	sym.mixHash(msg[:keySize])
	k, err := dh(static, re) // es
	if err != nil {
		return nil, err
	}
	if err := sym.mixKey(k); err != nil {
		return nil, err
	}
	sPlain, err := sym.decryptAndHash(msg[keySize : 2*keySize+tagSize]) // s
	if err != nil {
		return nil, err
	}
	rs, err := ParsePublic(sPlain)
	if err != nil {
		return nil, ErrHandshake
	}
	if k, err = dh(static, rs); err != nil { // ss
		return nil, err
	}
	if err := sym.mixKey(k); err != nil {
		return nil, err
	}
	ts, err := sym.decryptAndHash(msg[2*keySize+tagSize:])
	if err != nil {
		return nil, err
	}
	return &Request{ClientPub: rs, Timestamp: binary.BigEndian.Uint64(ts), sym: sym, re: re}, nil
}

// Accept формирует ответ клиенту и возвращает ключи транспорта.
// Вызывать только после проверки ClientPub и Timestamp.
func (r *Request) Accept() ([]byte, *Keys, error) {
	e, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	msg := append([]byte(nil), e.PublicKey().Bytes()...)
	r.sym.mixHash(e.PublicKey().Bytes())
	for _, pub := range []*ecdh.PublicKey{r.re, r.ClientPub} { // ee, se
		k, err := dh(e, pub)
		if err != nil {
			return nil, nil, err
		}
		if err := r.sym.mixKey(k); err != nil {
			return nil, nil, err
		}
	}
	msg = append(msg, r.sym.encryptAndHash(nil)...)
	k1, k2 := r.sym.split()
	return msg, &Keys{Send: k2, Recv: k1}, nil
}

// ---------- транспорт ----------

// Keys — ключи направлений после рукопожатия.
type Keys struct{ Send, Recv [32]byte }

// Session шифрует пакеты поверх потока. ReadPacket и WritePacket можно
// вызывать параллельно друг с другом, но каждый — только из одной горутины.
//
// Открытый текст кадра: [2 байта длины пакета][пакет][случайный padding],
// чтобы длины зашифрованных кадров не повторяли длины IP-пакетов.
type Session struct {
	w, r   cipher.AEAD
	wn, rn uint64
	rw     io.ReadWriter
	write  func(io.Writer, []byte) error
	read   func(io.Reader, []byte) ([]byte, error)
	rbuf   []byte
	pbuf   []byte
	wbuf   []byte
}

// MaxPadding — верхняя граница случайного padding на пакет.
const MaxPadding = 128

// NewSession создаёт сессию. write/read — функции кадрирования (см. пакет frame).
func NewSession(k *Keys, rw io.ReadWriter,
	write func(io.Writer, []byte) error,
	read func(io.Reader, []byte) ([]byte, error)) (*Session, error) {
	w, err := newAEAD(k.Send[:])
	if err != nil {
		return nil, err
	}
	r, err := newAEAD(k.Recv[:])
	if err != nil {
		return nil, err
	}
	return &Session{w: w, r: r, rw: rw, write: write, read: read,
		rbuf: make([]byte, 65535), pbuf: make([]byte, 65535), wbuf: make([]byte, 0, 65535)}, nil
}

// WritePacket шифрует и отправляет один пакет.
func (s *Session) WritePacket(p []byte) error {
	if s.wn == math.MaxUint64 {
		return ErrNonce
	}
	pad := mrand.IntN(MaxPadding)
	if 2+len(p)+pad+tagSize > 65535 {
		pad = 0
		if 2+len(p)+tagSize > 65535 {
			return errors.New("noise: packet too large")
		}
	}
	pt := s.wbuf[:2+len(p)+pad]
	binary.BigEndian.PutUint16(pt, uint16(len(p)))
	copy(pt[2:], p)
	clear(pt[2+len(p):])
	ct := s.w.Seal(nil, nonce(s.wn), pt, nil)
	s.wn++
	return s.write(s.rw, ct)
}

// ReadPacket читает и расшифровывает один пакет в buf.
func (s *Session) ReadPacket(buf []byte) ([]byte, error) {
	ct, err := s.read(s.rw, s.rbuf)
	if err != nil {
		return nil, err
	}
	if s.rn == math.MaxUint64 {
		return nil, ErrNonce
	}
	pt, err := s.r.Open(s.pbuf[:0], nonce(s.rn), ct, nil)
	if err != nil || len(pt) < 2 {
		return nil, errors.New("noise: decrypt failed")
	}
	s.rn++
	n := int(binary.BigEndian.Uint16(pt))
	if 2+n > len(pt) || n > len(buf) {
		return nil, errors.New("noise: bad packet length")
	}
	return buf[:copy(buf, pt[2:2+n])], nil
}
