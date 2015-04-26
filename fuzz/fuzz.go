package fuzz

import "github.com/gorilla/securecookie"

var hashKey = []byte("very-secret12345")
var blockKey = []byte("a-lot-secret1234")
var s = securecookie.New(hashKey, blockKey)

func Fuzz(data []byte) int {
	var m int
	err := s.Decode("fuzz", string(data), &m)
	if err != nil {
		return 0
	}
	encoded, err := s.Encode("fuzz", m)
	if err != nil {
		panic(err)
	}
	if encoded != string(data) {
		panic("not the same")
	}
	return 1
}
