package securecookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"sync"

	"golang.org/x/crypto/chacha20"
)

const (
	nameMaxLen   = 127
	keyLen       = 32
	macLen       = 16
	headerLen    = 8
	macHeaderLen = macLen + headerLen
	version      = 1
)

func (s *SecureCookie) prepareCompact() {
	bl := hmac.New(sha256.New, s.hashKey)
	_, _ = bl.Write(s.blockKey)
	copy(s.compactBlockKey[:], bl.Sum(nil))

	s.macPool = &sync.Pool{
		New: func() interface{} {
			hsh := hmac.New(sha256.New, s.hashKey)
			return &macbuf{Hash: hsh}
		},
	}
}

func (s *SecureCookie) encodeCompact(name string, serialized []byte) (string, error) {
	// Check length
	encodedLen := base64.URLEncoding.EncodedLen(len(serialized) + macLen + headerLen)
	if s.maxLength != 0 && encodedLen > s.maxLength {
		return "", errEncodedValueTooLong
	}

	// form message
	r := make([]byte, headerLen+macLen+len(serialized))
	macHeader, body := r[:macHeaderLen], r[macHeaderLen:]
	copy(body, serialized)

	header, mac := macHeader[:headerLen], macHeader[headerLen:]
	composeHeader(version, timestampNano(), header)

	// Mac
	s.compactMac(header, name, body, mac)

	// Encrypt (if needed)
	s.compactXorStream(macHeader, body)

	// Encode
	return base64.RawURLEncoding.EncodeToString(r), nil
}

func (s *SecureCookie) decodeCompact(name string, encoded string, dest interface{}) error {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return cookieError{cause: err, typ: decodeError, msg: "base64 decode failed"}
	}

	if len(encoded) < macHeaderLen {
		return errValueToDecodeTooShort
	}

	macHeader, body := decoded[:macHeaderLen], decoded[macHeaderLen:]
	header, mac := macHeader[:headerLen], macHeader[headerLen:]

	// Decompose
	v, ts := decomposeHeader(header)
	if v != version {
		// there is only version currently
		return errVersionDoesntMatch
	}

	// Check time
	now := timestampNano()
	if s.maxAge > 0 && ts+secs2nano(s.maxAge) < now {
		return errTimestampExpired
	}
	if s.minAge > 0 && ts+secs2nano(s.minAge) > now {
		return errTimestampExpired
	}

	// Decrypt (if need)
	s.compactXorStream(macHeader, body)

	// Check MAC
	var macCheck [macLen]byte
	s.compactMac(header, name, body, macCheck[:])
	if subtle.ConstantTimeCompare(mac, macCheck[:]) == 0 {
		return ErrMacInvalid
	}

	// Deserialize
	if err := s.sz.Deserialize(body, dest); err != nil {
		return cookieError{cause: err, typ: decodeError}
	}

	return nil
}

type macbuf struct {
	hash.Hash
	nameLen [4]byte
	sum     [32]byte
}

func (m *macbuf) Reset() {
	m.Hash.Reset()
	m.sum = [32]byte{}
}

func (s *SecureCookie) compactMac(header []byte, name string, body, mac []byte) {
	enc := s.macPool.Get().(*macbuf)

	binary.BigEndian.PutUint32(enc.nameLen[:], uint32(len(name)))
	_, _ = enc.Write(header)
	_, _ = enc.Write(enc.nameLen[:])
	_, _ = enc.Write([]byte(name))
	_, _ = enc.Write(body)

	copy(mac, enc.Sum(enc.sum[:0]))

	enc.Reset()
	s.macPool.Put(enc)
}

func (s *SecureCookie) compactXorStream(nonce, body []byte) {
	if len(s.blockKey) == 0 { // no blockKey - no encryption
		return
	}
	stream, err := chacha20.NewUnauthenticatedCipher(s.compactBlockKey[:], nonce)
	if err != nil {
		panic("stream initialization failed")
	}
	stream.XORKeyStream(body, body)
}

func composeHeader(v byte, t int64, header []byte) {
	ut := uint64(t) >> 8 // clear highest octet for version
	binary.BigEndian.PutUint64(header, ut)
	header[0] = v
}

func decomposeHeader(header []byte) (v byte, t int64) {
	v = header[0]
	ut := binary.BigEndian.Uint64(header)
	t = int64(ut << 8)
	return
}

func secs2nano(t int64) int64 {
	return t * 1000000000
}
