// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securecookie

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"
)

// Error is the interface of all errors returned by functions in this library.
type Error interface {
	error

	// IsUsage returns true for errors indicating the client code probably
	// uses this library incorrectly.  For example, the client may have
	// failed to provide a valid hash key, or may have failed to configure
	// the Serializer adequately for encoding value.
	IsUsage() bool

	// IsDecode returns true for errors indicating that a cookie could not
	// be decoded and validated.  Since cookies are usually untrusted
	// user-provided input, errors of this type should be expected.
	// Usually, the proper action is simply to reject the request.
	IsDecode() bool

	// IsInternal returns true for unexpected errors occurring in the
	// securecookie implementation.
	IsInternal() bool

	// Cause, if it returns a non-nil value, indicates that this error was
	// propagated from some underlying library.  If this method returns nil,
	// this error was raised directly by this library.
	//
	// Cause is provided principally for debugging/logging purposes; it is
	// rare that application logic should perform meaningfully different
	// logic based on Cause.  See, for example, the caveats described on
	// (MultiError).Cause().
	Cause() error
}

const (
	keyLength      = 32
	nonceLength    = 24
	valueSeparator = "|"
)

// errorType is a bitmask giving the error type(s) of an cookieError value.
type errorType int

const (
	usageError = errorType(1 << iota)
	decodeError
	internalError
)

type cookieError struct {
	typ   errorType
	msg   string
	cause error
}

func (e cookieError) IsUsage() bool    { return (e.typ & usageError) != 0 }
func (e cookieError) IsDecode() bool   { return (e.typ & decodeError) != 0 }
func (e cookieError) IsInternal() bool { return (e.typ & internalError) != 0 }

func (e cookieError) Cause() error { return e.cause }

func (e cookieError) Error() string {
	parts := []string{"securecookie: "}
	if e.msg == "" {
		parts = append(parts, "error")
	} else {
		parts = append(parts, e.msg)
	}
	if c := e.Cause(); c != nil {
		parts = append(parts, " - caused by: ", c.Error())
	}
	return strings.Join(parts, "")
}

var (
	errGeneratingIV        = cookieError{typ: internalError, msg: "failed to generate random iv"}
	errNoCodecs            = cookieError{typ: usageError, msg: "no codecs provided"}
	errHashKeyNotSet       = cookieError{typ: usageError, msg: "hash key is not set"}
	errBlockKeyNotSet      = cookieError{typ: usageError, msg: "block key is not set"}
	errEncodedValueTooLong = cookieError{typ: usageError, msg: "the value is too long"}

	errValueToDecodeTooLong = cookieError{typ: decodeError, msg: "the value is too long"}
	errTimestampInvalid     = cookieError{typ: decodeError, msg: "invalid timestamp"}
	errTimestampTooNew      = cookieError{typ: decodeError, msg: "timestamp is too new"}
	errTimestampExpired     = cookieError{typ: decodeError, msg: "expired timestamp"}
	errDecryptionFailed     = cookieError{typ: decodeError, msg: "the value could not be decrypted"}
	errValueNotByte         = cookieError{typ: decodeError, msg: "value not a []byte."}
	errValueNotBytePtr      = cookieError{typ: decodeError, msg: "value not a pointer to []byte."}

	// ErrMacInvalid indicates that cookie decoding failed because the HMAC
	// could not be extracted and verified.  Direct use of this error
	// variable is deprecated; it is public only for legacy compatibility,
	// and may be privatized in the future, as it is rarely useful to
	// distinguish between this error and other Error implementations.
	ErrMacInvalid = cookieError{typ: decodeError, msg: "the value is not valid"}
)

type cookie struct {
	Name      string
	Timestamp int64
	Value     []byte
}

// New returns a new SecureCookie.
//
// key should be ...
//
func New(key []byte) (*SecureCookie, error) {
	if l := len(key); l != keyLength {
		return nil, errors.Errorf("key length is invalid: got %d, require %d", l, keyLength)
	}

	s := &SecureCookie{
		maxAge:    86400 * 30,
		maxLength: 4096,
		sz:        JSONEncoder{},
	}

	copy(s.key[:], key)

	return s, nil
}

// SecureCookie encodes and decodes authenticated and optionally encrypted
// cookie values.
type SecureCookie struct {
	key       [keyLength]byte
	maxLength int
	maxAge    int64
	minAge    int64
	err       error
	sz        Serializer
	// For testing purposes, the function that returns the current timestamp.
	// If not set, it will use time.Now().UTC().Unix().
	timeFunc func() int64
}

// MaxLength restricts the maximum length, in bytes, for the cookie value.
//
// Default is 4096, which is the maximum value accepted by Internet Explorer.
func (s *SecureCookie) MaxLength(value int) *SecureCookie {
	s.maxLength = value
	return s
}

// MaxAge restricts the maximum age, in seconds, for the cookie value.
//
// Default is 86400 * 30. Set it to 0 for no restriction.
func (s *SecureCookie) MaxAge(value int) *SecureCookie {
	s.maxAge = int64(value)
	return s
}

// MinAge restricts the minimum age, in seconds, for the cookie value.
//
// Default is 0 (no restriction).
func (s *SecureCookie) MinAge(value int) *SecureCookie {
	s.minAge = int64(value)
	return s
}

// SetSerializer sets the encoding/serialization method for cookies. Default is
// encoding/json.
func (s *SecureCookie) SetSerializer(sz Serializer) *SecureCookie {
	s.sz = sz

	return s
}

// Encode encodes a cookie value.
//
// The name argument is the cookie name. It is stored with the encoded value.
// The value argument is the value to be encoded. It can be any value that can
// be encoded using the currently selected serializer; see SetSerializer().
//
// It is the client's responsibility to ensure that value, when encoded using
// the current serialization/encryption settings on s and then base64-encoded,
// is shorter than the maximum permissible length.
func (s *SecureCookie) Encode(name string, value interface{}) (string, error) {
	if s.err != nil {
		return "", s.err
	}

	// 1. Serialize the given value
	data, err := s.sz.Serialize(value)
	if err != nil {
		return "", errors.Wrap(err, "could not serialize value")
	}

	// 2. Encrypt & MAC
	var nonce [nonceLength]byte

	// Nonces must not be re-used for the same key. Secretbox uses XSalsa20, which
	// has a nonce length of 192 bits, giving us a 1 x 10^-30 chance of a nonce
	// collision.

	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", errors.Wrapf(err, "failed to generate a nonce")
	}

	// We create a buffer of "name|timestamp|serializedData" so that we can verify
	// the validity of the timestamp after decrypting, but before deserializing.
	buf := new(bytes.Buffer)
	buf.WriteString(name + valueSeparator)
	buf.WriteString(strconv.FormatInt(s.timestamp(), 10) + valueSeparator)
	buf.Write(data)

	ctext := secretbox.Seal(
		nonce[:],
		buf.Bytes(),
		&nonce,
		&s.key,
	)

	// 3. Encode the output into a cookie-safe format
	encoded := encode(ctext)

	// 4. Check length of encoded value
	if len(encoded) > s.maxLength {
		return "", errors.Errorf("encoded cookie value exceeds max length of %d bytes", s.maxLength)
	}

	return string(encoded), nil
}

// Decode decodes a cookie value.
//
// The name argument is the cookie name. It must be the same name used when
// it was stored. The value argument is the encoded cookie value. The dst
// argument is where the cookie will be decoded. It must be a pointer.
func (s *SecureCookie) Decode(name, value string, dst interface{}) error {
	if s.err != nil {
		return s.err
	}

	// 1. Check length.
	if s.maxLength != 0 && len(value) > s.maxLength {
		return errValueToDecodeTooLong
	}

	// 2. Decode from base64.
	decoded, err := decode([]byte(value))
	if err != nil {
		return err
	}

	if len(decoded) < nonceLength {
		return errors.New("decoded cookie value is invalid: too short")
	}

	// 3. Decrypt and verify the contents
	var nonce [nonceLength]byte
	copy(nonce[:], decoded[:24])

	plaintext, valid := secretbox.Open(
		nil,
		decoded[24:],
		&nonce,
		&s.key,
	)
	if !valid {
		return errors.New("failed to decrypt cookie value")
	}

	// 4. Verify the name & timestamp
	// parts[0] = name
	// parts[1] = timestamp
	// parts[2] = serialized data
	parts := bytes.SplitN(plaintext, []byte(valueSeparator), 2)
	if len(parts) != 3 {
		return errors.New("invalid cookie value: could not split into name|timestamp|serializedData")
	}

	if string(parts[0]) != name {
		return errors.Errorf("cookie name mismatch: got %s, expected %s", string(parts[0]), name)
	}

	ts, err := strconv.ParseInt(string(parts[1]), 10, 64)
	if err != nil {
		return errors.Wrap(err, "timestamp format invalid")
	}

	now := s.timestamp()
	if s.maxAge != 0 && ts > now {
		return errTimestampExpired
	}

	// 5. Deserialize the payload
	if err = s.sz.Deserialize(parts[2], dst); err != nil {
		return err
	}

	return nil
}

// timestamp returns the current timestamp, in seconds.
//
// For testing purposes, the function that generates the timestamp can be
// overridden. If not set, it will return time.Now().UTC().Unix().
func (s *SecureCookie) timestamp() int64 {
	if s.timeFunc == nil {
		return time.Now().UTC().Unix()
	}
	return s.timeFunc()
}

// encode encodes a value using base64.
func encode(value []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(value)))
	base64.URLEncoding.Encode(encoded, value)

	return encoded
}

// decode decodes a cookie using base64.
func decode(value []byte) ([]byte, error) {
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(value)))
	b, err := base64.URLEncoding.Decode(decoded, value)
	if err != nil {
		return nil, err
	}

	return decoded[:b], nil
}

// GenerateRandomKey returns securely generated random bytes, suitable for use
// as a crytographic key.
//
// It will return an error if the system's secure random number generator fails
// to function correctly, in which case the caller should not continue.
func GenerateRandomKey(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
