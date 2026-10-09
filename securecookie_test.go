// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securecookie

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	fuzz "github.com/google/gofuzz"
)

// Asserts that cookieError and MultiError are Error implementations.
var _ Error = cookieError{}
var _ Error = MultiError{}

var testCookies = []interface{}{
	map[string]string{"foo": "bar"},
	map[string]string{"baz": "ding"},
}

var testStrings = []string{"foo", "bar", "baz"}

func TestSecureCookie(t *testing.T) {
	// TODO test too old / too new timestamps
	s1 := New([]byte("12345"), []byte("1234567890123456"))
	s2 := New([]byte("54321"), []byte("6543210987654321"))
	value := map[string]interface{}{
		"foo": "bar",
		"baz": 128,
	}

	for i := 0; i < 50; i++ {
		// Running this multiple times to check if any special character
		// breaks encoding/decoding.
		encoded, err1 := s1.Encode("sid", value)
		if err1 != nil {
			t.Error(err1)
			continue
		}
		dst := make(map[string]interface{})
		err2 := s1.Decode("sid", encoded, &dst)
		if err2 != nil {
			t.Fatalf("%v: %v", err2, encoded)
		}
		if !reflect.DeepEqual(dst, value) {
			t.Fatalf("Expected %v, got %v.", value, dst)
		}
		dst2 := make(map[string]interface{})
		err3 := s2.Decode("sid", encoded, &dst2)
		if err3 == nil {
			t.Fatalf("Expected failure decoding.")
		}
		err4, ok := err3.(Error)
		if !ok {
			t.Fatalf("Expected error to implement Error, got: %#v", err3)
		}
		if !err4.IsDecode() {
			t.Fatalf("Expected DecodeError, got: %#v", err4)
		}

		// Test other error type flags.
		if err4.IsUsage() {
			t.Fatalf("Expected IsUsage() == false, got: %#v", err4)
		}
		if err4.IsInternal() {
			t.Fatalf("Expected IsInternal() == false, got: %#v", err4)
		}
	}
}

func TestSecureCookieNilKey(t *testing.T) {
	s1 := New(nil, nil)
	value := map[string]interface{}{
		"foo": "bar",
		"baz": 128,
	}
	_, err := s1.Encode("sid", value)
	if err != errHashKeyNotSet {
		t.Fatal("Wrong error returned:", err)
	}
}

func TestDecodeInvalid(t *testing.T) {
	// List of invalid cookies, which must not be accepted, base64-decoded
	// (they will be encoded before passing to Decode).
	invalidCookies := []string{
		"",
		" ",
		"\n",
		"||",
		"|||",
		"cookie",
	}
	s := New([]byte("12345"), nil)
	var dst string
	for i, v := range invalidCookies {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding,
			base64.URLEncoding,
		} {
			err := s.Decode("name", enc.EncodeToString([]byte(v)), &dst)
			if err == nil {
				t.Fatalf("%d: expected failure decoding", i)
			}
			err2, ok := err.(Error)
			if !ok || !err2.IsDecode() {
				t.Fatalf("%d: Expected IsDecode(), got: %#v", i, err)
			}
		}
	}
}

func TestAuthentication(t *testing.T) {
	hash := hmac.New(sha256.New, []byte("secret-key"))
	for _, value := range testStrings {
		hash.Reset()
		signed := createMac(hash, []byte(value))
		hash.Reset()
		err := verifyMac(hash, []byte(value), signed)
		if err != nil {
			t.Error(err)
		}
	}
}

func TestEncryption(t *testing.T) {
	block, err := aes.NewCipher([]byte("1234567890123456"))
	if err != nil {
		t.Fatalf("Block could not be created")
	}
	var encrypted, decrypted []byte
	for _, value := range testStrings {
		if encrypted, err = encrypt(block, []byte(value)); err != nil {
			t.Error(err)
		} else {
			if decrypted, err = decrypt(block, encrypted); err != nil {
				t.Error(err)
			}
			if string(decrypted) != value {
				t.Errorf("Expected %v, got %v.", value, string(decrypted))
			}
		}
	}
}

func TestGobSerialization(t *testing.T) {
	var (
		sz           GobEncoder
		serialized   []byte
		deserialized map[string]string
		err          error
	)
	for _, value := range testCookies {
		if serialized, err = sz.Serialize(value); err != nil {
			t.Error(err)
		} else {
			deserialized = make(map[string]string)
			if err = sz.Deserialize(serialized, &deserialized); err != nil {
				t.Error(err)
			}
			if fmt.Sprintf("%v", deserialized) != fmt.Sprintf("%v", value) {
				t.Errorf("Expected %v, got %v.", value, deserialized)
			}
		}
	}
}

func TestJSONSerialization(t *testing.T) {
	var (
		sz           JSONEncoder
		serialized   []byte
		deserialized map[string]string
		err          error
	)
	for _, value := range testCookies {
		if serialized, err = sz.Serialize(value); err != nil {
			t.Error(err)
		} else {
			deserialized = make(map[string]string)
			if err = sz.Deserialize(serialized, &deserialized); err != nil {
				t.Error(err)
			}
			if fmt.Sprintf("%v", deserialized) != fmt.Sprintf("%v", value) {
				t.Errorf("Expected %v, got %v.", value, deserialized)
			}
		}
	}
}

func TestNopSerialization(t *testing.T) {
	cookieData := "fooobar123"
	sz := NopEncoder{}

	if _, err := sz.Serialize(cookieData); err != errValueNotByte {
		t.Fatal("Expected error passing string")
	}
	dat, err := sz.Serialize([]byte(cookieData))
	if err != nil {
		t.Fatal(err)
	}
	if (string(dat)) != cookieData {
		t.Fatal("Expected serialized data to be same as source")
	}

	var dst []byte
	if err = sz.Deserialize(dat, dst); err != errValueNotBytePtr {
		t.Fatal("Expect error unless you pass a *[]byte")
	}
	if err = sz.Deserialize(dat, &dst); err != nil {
		t.Fatal(err)
	}
	if (string(dst)) != cookieData {
		t.Fatal("Expected deserialized data to be same as source")
	}
}

func TestEncoding(t *testing.T) {
	for _, value := range testStrings {
		encoded := encode([]byte(value))
		decoded, err := decode(encoded)
		if err != nil {
			t.Error(err)
		} else if string(decoded) != value {
			t.Errorf("Expected %v, got %s.", value, string(decoded))
		}
	}
}

func TestMultiError(t *testing.T) {
	s1, s2 := New(nil, nil), New(nil, nil)
	_, err := EncodeMulti("sid", "value", s1, s2)
	if len(err.(MultiError)) != 2 {
		t.Errorf("Expected 2 errors, got %s.", err)
	} else {
		if !strings.Contains(err.Error(), "hash key is not set") {
			t.Errorf("Expected missing hash key error, got %s.", err.Error())
		}
		ourErr, ok := err.(Error)
		if !ok || !ourErr.IsUsage() {
			t.Fatalf("Expected error to be a usage error; got %#v", err)
		}
		if ourErr.IsDecode() {
			t.Errorf("Expected error NOT to be a decode error; got %#v", ourErr)
		}
		if ourErr.IsInternal() {
			t.Errorf("Expected error NOT to be an internal error; got %#v", ourErr)
		}
	}
}

func TestMultiNoCodecs(t *testing.T) {
	_, err := EncodeMulti("foo", "bar")
	if err != errNoCodecs {
		t.Errorf("EncodeMulti: bad value for error, got: %v", err)
	}

	var dst []byte
	err = DecodeMulti("foo", "bar", &dst)
	if err != errNoCodecs {
		t.Errorf("DecodeMulti: bad value for error, got: %v", err)
	}
}

func TestMissingKey(t *testing.T) {
	emptyKeys := [][]byte{
		nil,
		[]byte(""),
	}

	for _, key := range emptyKeys {
		s1 := New(key, nil)

		var dst []byte
		err := s1.Decode("sid", "value", &dst)
		if err != errHashKeyNotSet {
			t.Fatalf("Expected %#v, got %#v", errHashKeyNotSet, err)
		}
		if err2, ok := err.(Error); !ok || !err2.IsUsage() {
			t.Errorf("Expected missing hash key to be IsUsage(); was %#v", err)
		}
	}
}

// ----------------------------------------------------------------------------

type FooBar struct {
	Foo int
	Bar string
}

func TestCustomType(t *testing.T) {
	s1 := New([]byte("12345"), []byte("1234567890123456"))
	// Type is not registered in gob. (!!!)
	src := &FooBar{42, "bar"}
	encoded, _ := s1.Encode("sid", src)

	dst := &FooBar{}
	_ = s1.Decode("sid", encoded, dst)
	if dst.Foo != 42 || dst.Bar != "bar" {
		t.Fatalf("Expected %#v, got %#v", src, dst)
	}
}

type Cookie struct {
	B bool
	I int
	S string
}

func FuzzEncodeDecode(f *testing.F) {
	fuzzer := fuzz.New()
	s1 := New([]byte("12345"), []byte("1234567890123456"))
	s1.maxLength = 0

	for i := 0; i < 100000; i++ {
		var c Cookie
		fuzzer.Fuzz(&c)
		f.Add(c.B, c.I, c.S)
	}

	f.Fuzz(func(t *testing.T, b bool, i int, s string) {
		c := Cookie{b, i, s}
		encoded, err := s1.Encode("sid", c)
		if err != nil {
			t.Errorf("Encode failed: %v", err)
		}
		dc := Cookie{}
		err = s1.Decode("sid", encoded, &dc)
		if err != nil {
			t.Errorf("Decode failed: %v", err)
		}
		if dc != c {
			t.Fatalf("Expected %v, got %v.", s, dc)
		}
	})
}

type errorRandReader struct {
	err error
}

func (r *errorRandReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

type partialRandReader struct {
	allowed int
	err     error
}

func (r *partialRandReader) Read(p []byte) (n int, err error) {
	if r.allowed <= 0 {
		return 0, r.err
	}
	n = len(p)
	if n > r.allowed {
		n = r.allowed
	}
	for i := 0; i < n; i++ {
		p[i] = byte(i + 1)
	}
	r.allowed -= n
	return n, nil
}

func TestGenerateRandomKeySafe(t *testing.T) {
	for _, length := range []int{16, 24, 32, 64} {
		key1, err := GenerateRandomKeySafe(length)
		if err != nil {
			t.Fatalf("GenerateRandomKeySafe(%d) returned error: %v", length, err)
		}
		if len(key1) != length {
			t.Fatalf("GenerateRandomKeySafe(%d) returned key length %d, want %d", length, len(key1), length)
		}

		key2, err := GenerateRandomKeySafe(length)
		if err != nil {
			t.Fatalf("GenerateRandomKeySafe(%d) second call returned error: %v", length, err)
		}
		if bytes.Equal(key1, key2) {
			t.Fatalf("GenerateRandomKeySafe(%d) returned identical keys across calls", length)
		}
	}

	keyZero, err := GenerateRandomKeySafe(0)
	if err != nil {
		t.Fatalf("GenerateRandomKeySafe(0) returned error: %v", err)
	}
	if len(keyZero) != 0 {
		t.Fatalf("GenerateRandomKeySafe(0) length = %d, want 0", len(keyZero))
	}
}

func TestGenerateRandomKeySafeInvalidLength(t *testing.T) {
	for _, length := range []int{-1, -16} {
		key, err := GenerateRandomKeySafe(length)
		if key != nil {
			t.Fatalf("GenerateRandomKeySafe(%d) returned non-nil key", length)
		}
		if err == nil {
			t.Fatalf("GenerateRandomKeySafe(%d) expected error, got nil", length)
		}
		if !errors.Is(err, errInvalidKeyLength) {
			t.Fatalf("GenerateRandomKeySafe(%d) error = %v, want errInvalidKeyLength", length, err)
		}
		cookieErr, ok := err.(Error)
		if !ok {
			t.Fatalf("GenerateRandomKeySafe(%d) error does not implement Error interface", length)
		}
		if !cookieErr.IsUsage() {
			t.Fatalf("GenerateRandomKeySafe(%d) error.IsUsage() = false, want true", length)
		}
		if cookieErr.IsInternal() {
			t.Fatalf("GenerateRandomKeySafe(%d) error.IsInternal() = true, want false", length)
		}
		if cookieErr.IsDecode() {
			t.Fatalf("GenerateRandomKeySafe(%d) error.IsDecode() = true, want false", length)
		}
	}
}

func TestGenerateRandomKeySafeReaderError(t *testing.T) {
	origReader := rand.Reader
	defer func() { rand.Reader = origReader }()

	injectedErr := errors.New("simulated csprng read failure")
	rand.Reader = &errorRandReader{err: injectedErr}

	key, err := GenerateRandomKeySafe(32)
	if key != nil {
		t.Fatalf("expected nil key on reader error, got %v", key)
	}
	if err == nil {
		t.Fatal("expected error on reader error, got nil")
	}
	if !errors.Is(err, injectedErr) {
		t.Fatalf("errors.Is(err, injectedErr) = false, err = %v", err)
	}
	if !errors.Is(err, errGeneratingKey) {
		t.Fatalf("errors.Is(err, errGeneratingKey) = false, err = %v", err)
	}

	cookieErr, ok := err.(Error)
	if !ok {
		t.Fatalf("error does not implement Error interface: %#v", err)
	}
	if !cookieErr.IsInternal() {
		t.Fatalf("cookieErr.IsInternal() = false, want true")
	}
	if cookieErr.IsUsage() {
		t.Fatalf("cookieErr.IsUsage() = true, want false")
	}
	if cookieErr.IsDecode() {
		t.Fatalf("cookieErr.IsDecode() = true, want false")
	}
	if cookieErr.Cause() != injectedErr {
		t.Fatalf("cookieErr.Cause() = %v, want %v", cookieErr.Cause(), injectedErr)
	}
}

func TestGenerateRandomKeySafePartialReadError(t *testing.T) {
	origReader := rand.Reader
	defer func() { rand.Reader = origReader }()

	rand.Reader = &partialRandReader{allowed: 10, err: io.ErrUnexpectedEOF}

	key, err := GenerateRandomKeySafe(32)
	if key != nil {
		t.Fatalf("expected nil key on partial read error, got %v", key)
	}
	if err == nil {
		t.Fatal("expected error on partial read error, got nil")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("errors.Is(err, io.ErrUnexpectedEOF) = false, err = %v", err)
	}
	cookieErr, ok := err.(Error)
	if !ok {
		t.Fatalf("error does not implement Error interface: %#v", err)
	}
	if !cookieErr.IsInternal() {
		t.Fatalf("cookieErr.IsInternal() = false, want true")
	}
}

func TestGenerateRandomKey(t *testing.T) {
	key := GenerateRandomKey(32)
	if len(key) != 32 {
		t.Fatalf("GenerateRandomKey(32) length = %d, want 32", len(key))
	}

	keyNegative := GenerateRandomKey(-1)
	if keyNegative != nil {
		t.Fatalf("GenerateRandomKey(-1) returned non-nil key: %v", keyNegative)
	}

	origReader := rand.Reader
	defer func() { rand.Reader = origReader }()

	rand.Reader = &errorRandReader{err: errors.New("read error")}
	keyFailed := GenerateRandomKey(32)
	if keyFailed != nil {
		t.Fatalf("GenerateRandomKey(32) with failed reader returned non-nil key: %v", keyFailed)
	}
}

