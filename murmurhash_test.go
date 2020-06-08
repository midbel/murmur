package murmur

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMurmurHash128x64v3(t *testing.T) {
	var (
		hash1 uint64 = 0xB386ADE2FEE9E4BC
		hash2 uint64 = 0x7F4B6E4074E3E20A
		hash         = make([]byte, 16)
		str          = "the quick brown fox jumps over the lazy dog"
	)
	binary.BigEndian.PutUint64(hash, hash1)
	binary.BigEndian.PutUint64(hash[8:], hash2)

	digest := Murmur128x64v3(0)
	digest.Write([]byte(str))
	sum := digest.Sum(nil)
	if !bytes.Equal(hash, sum) {
		t.Errorf("invalid hash! want %x, got %x", hash, sum)
	}
}

func TestMurmurHash128x86v3(t *testing.T) {
	var (
		hash1 uint64 = 0xFDB47DAF02170D40
		hash2 uint64 = 0x3F6093539B388AF2
		hash         = make([]byte, 16)
		str          = "the quick brown fox jumps over the lazy dog"
	)
	binary.BigEndian.PutUint64(hash, hash1)
	binary.BigEndian.PutUint64(hash[8:], hash2)

	digest := Murmur128x86v3(0)
	digest.Write([]byte(str))
	sum := digest.Sum(nil)
	if !bytes.Equal(hash, sum) {
		t.Errorf("invalid hash! want %x, got %x", hash, sum)
	}
}

func TestMurmurHash32x86v3(t *testing.T) {
	var (
		want uint32 = 0xFF62DE02
		hash        = make([]byte, 4)
		str         = "the quick brown fox jumps over the lazy dog"
	)

	digest := Murmur32x86v3(0)
	digest.Write([]byte(str))

	binary.BigEndian.PutUint32(hash, want)
	if sum := digest.Sum(nil); !bytes.Equal(hash, sum) {
		t.Errorf("invalid hash! want %x, got %x", want, sum)
	}
}
