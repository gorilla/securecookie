package securecookie

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"sync"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"
)

const (
	nameMaxLen = 127
	keyLen     = 32
	macLen     = 15
	timeLen    = 8
	versionLen = 1
	version    = 0
)

func (s *SecureCookie) prepareCompactKeys() {
	// initialize for compact encoding even if no genCompact set to allow
	// two step migration.
	s.compactHashKey = blake2s.Sum256(s.hashKey)
	bl, _ := blake2s.New256(s.compactHashKey[:])
	_, _ = bl.Write(s.blockKey)
	copy(s.compactBlockKey[:], bl.Sum(nil))
}

func (s *SecureCookie) encodeCompact(name string, serialized []byte) (string, error) {
	if len(name) > nameMaxLen {
		return "", errNameTooLong
	}

	// Check length
	encodedLen := base64.URLEncoding.EncodedLen(len(serialized) + macLen + timeLen + versionLen)
	if s.maxLength != 0 && encodedLen > s.maxLength {
		return "", errEncodedValueTooLong
	}

	// form message
	r := make([]byte, versionLen+macLen+timeLen+len(serialized))
	r[0] = version
	m := r[versionLen:]
	tag, body := m[:macLen], m[macLen:]
	binary.LittleEndian.PutUint64(body, uint64(timeShift(timestampNano())))
	copy(body[timeLen:], serialized)

	// Mac
	s.compactMac(version, name, body, tag)

	// Encrypt (if needed)
	s.compactXorStream(tag, body)

	// Encode
	return base64.RawURLEncoding.EncodeToString(r), nil
}

func (s *SecureCookie) decodeCompact(name string, encoded string, dest interface{}) error {
	if len(name) > nameMaxLen {
		return errNameTooLong
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return cookieError{cause: err, typ: decodeError, msg: "base64 decode failed"}
	}

	if len(encoded) < macLen+timeLen+versionLen {
		return errValueToDecodeTooShort
	}

	// Decompose
	if decoded[0] != version {
		// there is only version currently
		return errVersionDoesntMatch
	}

	m := decoded[versionLen:]
	tag, body := m[:macLen], m[macLen:]

	// Decrypt (if need)
	s.compactXorStream(tag, body)

	// Check time
	ts := int64(binary.LittleEndian.Uint64(body))
	now := timeShift(timestampNano())
	if s.maxAge > 0 && ts+secsShift(s.maxAge) < now {
		return errTimestampExpired
	}
	if s.minAge > 0 && ts+secsShift(s.minAge) > now {
		return errTimestampExpired
	}
	if !timeValid(ts) {
		// We are checking bytes we explicitely leaved as zero as preliminary
		// MAC check. We could do it because ChaCha20 has no known plaintext
		// issues.
		return ErrMacInvalid
	}

	// Verify
	var mac [macLen]byte
	s.compactMac(version, name, body, mac[:])
	if subtle.ConstantTimeCompare(mac[:], tag) == 0 {
		return ErrMacInvalid
	}

	// Deserialize
	if err := s.sz.Deserialize(body[timeLen:], dest); err != nil {
		return cookieError{cause: err, typ: decodeError}
	}

	return nil
}

var macPool = sync.Pool{New: func() interface{} {
	hsh, _ := blake2s.New256(nil)
	return &macbuf{Hash: hsh}
}}

type macbuf struct {
	hash.Hash
	buf [3 + nameMaxLen]byte
	sum [32]byte
}

func (m *macbuf) Reset() {
	m.Hash.Reset()
	m.buf = [3 + nameMaxLen]byte{}
	m.sum = [32]byte{}
}

func (s *SecureCookie) compactMac(version byte, name string, body, mac []byte) {
	enc := macPool.Get().(*macbuf)

	// While it is not "recommended" way to mix key in, it is still valid
	// because 1) Blake2b is not susceptible to length-extention attack, 2)
	// "recommended" way does almost same, just stores key length in other place
	// (it mixes length into constan iv itself).
	enc.buf[0] = version
	// name should not be longer than 127 bytes to fallback to varint in a future
	enc.buf[1] = byte(len(name))
	enc.buf[2] = keyLen
	copy(enc.buf[3:], name)

	_, _ = enc.Write(enc.buf[:3+len(name)])
	_, _ = enc.Write(s.hashKey[:])
	_, _ = enc.Write(body)

	copy(mac, enc.Sum(enc.sum[:0]))

	enc.Reset()
	macPool.Put(enc)
}

func (s *SecureCookie) compactXorStream(tag, body []byte) {
	if len(s.blockKey) == 0 { // no blockKey - no encryption
		return
	}
	key := s.compactBlockKey
	// Mix remaining tag bytes into key.
	// We may do it because ChaCha20 has no related keys issues.
	key[29] ^= tag[12]
	key[30] ^= tag[13]
	key[31] ^= tag[14]
	stream, err := chacha20.NewUnauthenticatedCipher(key[:], tag[:12])
	if err != nil {
		panic("stream initialization failed")
	}
	stream.XORKeyStream(body, body)
}

func timeShift(t int64) int64 {
	return t >> 16
}

func timeValid(t int64) bool {
	return (t >> (64 - 16)) == 0
}

func secsShift(t int64) int64 {
	return (t * 1000000000) >> 16
}
