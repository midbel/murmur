package murmur

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const (
	sizeBlock128 = 16
	sizeBlock32  = 4

	one128x64 uint64 = 0x87c37b91114253d5
	two128x64 uint64 = 0x4cf5ad432745937f

	one128x86   uint32 = 0x239b961b
	two128x86   uint32 = 0xab0e9789
	three128x86 uint32 = 0x38b34ae5
	four128x86  uint32 = 0xa1e38b93

	one32x86 = 0xcc9e2d51
	two32x86 = 0x1b873593
)

type murmur128x64v3 struct {
	buffer  [sizeBlock128]byte
	offset  int
	written int

	hash1 uint64
	hash2 uint64
	seed  uint64
}

func Murmur128x64v3(seed uint64) hash.Hash {
	var m murmur128x64v3
	m.seed = seed
	m.Reset()
	return &m
}

func (m *murmur128x64v3) Size() int { return sizeBlock128 }

func (m *murmur128x64v3) BlockSize() int { return sizeBlock128 }

func (m *murmur128x64v3) Write(bs []byte) (int, error) {
	length := len(bs)
	m.written += length
	if m.offset > 0 {
		i := copy(m.buffer[m.offset:], bs)
		m.offset += i
		if m.offset < sizeBlock128 {
			return length, nil
		}
		m.calculateBlock(m.buffer[:])
		bs, m.offset = bs[i:], 0
	}

	var (
		blocks = len(bs)/sizeBlock128
		written int
	)
	for i := 0; i < blocks; i++ {
		m.calculateBlock(bs[i*sizeBlock128:])
		written += sizeBlock128
	}
	if diff := len(bs)-written; diff > 0 {
		m.offset = copy(m.buffer[0:], bs[written:])
	}
	return length, nil
}

func (m *murmur128x64v3) Reset() {
	m.hash1 = m.seed
	m.hash2 = m.seed
	m.offset = 0
	m.written = 0
}

func (m *murmur128x64v3) Sum(bs []byte) []byte {
	y := *m
	sum := y.checksum()
	return append(bs, sum...)
}

func (m *murmur128x64v3) checksum() []byte {
	var (
		tail = m.buffer[:m.offset]
		k1   uint64
		k2   uint64
	)
	switch m.written & 15 {
	case 15:
		k2 ^= uint64(tail[14]) << 48
		fallthrough
	case 14:
		k2 ^= uint64(tail[13]) << 40
		fallthrough
	case 13:
		k2 ^= uint64(tail[12]) << 32
		fallthrough
	case 12:
		k2 ^= uint64(tail[11]) << 24
		fallthrough
	case 11:
		k2 ^= uint64(tail[10]) << 16
		fallthrough
	case 10:
		k2 ^= uint64(tail[9]) << 8
		fallthrough
	case 9:
		k2 ^= uint64(tail[8]) << 0
		k2 *= two128x64
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= one128x64
		m.hash2 ^= k2

		fallthrough
	case 8:
		k1 ^= uint64(tail[7]) << 56
		fallthrough
	case 7:
		k1 ^= uint64(tail[6]) << 48
		fallthrough
	case 6:
		k1 ^= uint64(tail[5]) << 40
		fallthrough
	case 5:
		k1 ^= uint64(tail[4]) << 32
		fallthrough
	case 4:
		k1 ^= uint64(tail[3]) << 24
		fallthrough
	case 3:
		k1 ^= uint64(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint64(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint64(tail[0]) << 0
		k1 *= one128x64
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= two128x64
		m.hash1 ^= k1
	}

	m.hash1 ^= uint64(m.written)
	m.hash2 ^= uint64(m.written)

	m.hash1 += m.hash2
	m.hash2 += m.hash1

	m.hash1 = finalMix64(m.hash1)
	m.hash2 = finalMix64(m.hash2)

	m.hash1 += m.hash2
	m.hash2 += m.hash1

	sum := make([]byte, sizeBlock128)
	binary.LittleEndian.PutUint64(sum, m.hash1)
	binary.LittleEndian.PutUint64(sum[8:], m.hash2)
	return sum
}

func (m *murmur128x64v3) calculateBlock(bs []byte) {
	tmp := binary.LittleEndian.Uint64(bs[0:])

	tmp *= one128x64
	tmp = bits.RotateLeft64(tmp, 31)
	tmp *= two128x64
	m.hash1 ^= tmp

	m.hash1 = bits.RotateLeft64(m.hash1, 27)
	m.hash1 += m.hash2
	m.hash1 = (m.hash1 * 5) + 0x52dce729

	tmp = binary.LittleEndian.Uint64(bs[8:])
	tmp *= two128x64
	tmp = bits.RotateLeft64(tmp, 33)
	tmp *= one128x64
	m.hash2 ^= tmp

	m.hash2 = bits.RotateLeft64(m.hash2, 31)
	m.hash2 += m.hash1
	m.hash2 = (m.hash2 * 5) + 0x38495ab5
}

type murmur128x86v3 struct {
	buffer  [sizeBlock128]byte
	offset  int
	written int

	hash1 uint32
	hash2 uint32
	hash3 uint32
	hash4 uint32

	seed uint32
}

func Murmur128x86v3(seed uint32) hash.Hash {
	var m murmur128x86v3
	m.seed = seed

	m.Reset()
	return &m
}

func (m *murmur128x86v3) Size() int { return sizeBlock128 }

func (m *murmur128x86v3) BlockSize() int { return sizeBlock128 }

func (m *murmur128x86v3) Write(bs []byte) (int, error) {
	length := len(bs)
	m.written += length
	if m.offset > 0 {
		i := copy(m.buffer[m.offset:], bs)
		m.offset += i
		if m.offset < sizeBlock128 {
			return length, nil
		}
		m.calculateBlock(m.buffer[:])
		bs, m.offset = bs[i:], 0
	}

	var (
		blocks = len(bs)/sizeBlock128
		written int
	)
	for i := 0; i < blocks; i++ {
		m.calculateBlock(bs[i*sizeBlock128:])
		written += sizeBlock128
	}
	if diff := len(bs)-written; diff > 0 {
		m.offset = copy(m.buffer[0:], bs[written:])
	}
	return length, nil
}

func (m *murmur128x86v3) Reset() {
	m.hash1 = m.seed
	m.hash2 = m.seed
	m.hash3 = m.seed
	m.hash4 = m.seed
	m.offset = 0
	m.written = 0
}

func (m *murmur128x86v3) Sum(bs []byte) []byte {
	y := *m
	sum := y.checksum()
	return append(bs, sum...)
}

func (m *murmur128x86v3) checksum() []byte {
	var (
		tail = m.buffer[:m.offset]
		k1   uint32
		k2   uint32
		k3   uint32
		k4   uint32
	)
	switch m.written & 15 {
	case 15:
		k4 ^= uint32(tail[14]) << 16
		fallthrough
	case 14:
		k4 ^= uint32(tail[13]) << 8
		fallthrough
	case 13:
		k4 ^= uint32(tail[12]) << 0
		k4 *= four128x86
		k4 = bits.RotateLeft32(k4, 18)
		k4 *= one128x86
		m.hash4 ^= k4
		fallthrough
	case 12:
		k3 ^= uint32(tail[11]) << 24
		fallthrough
	case 11:
		k3 ^= uint32(tail[10]) << 16
		fallthrough
	case 10:
		k3 ^= uint32(tail[9]) << 8
		fallthrough
	case 9:
		k3 ^= uint32(tail[8]) << 0
		k3 *= three128x86
		k3 = bits.RotateLeft32(k3, 17)
		k3 *= four128x86
		m.hash3 ^= k3
		fallthrough
	case 8:
		k2 ^= uint32(tail[7]) << 24
		fallthrough
	case 7:
		k2 ^= uint32(tail[6]) << 16
		fallthrough
	case 6:
		k2 ^= uint32(tail[5]) << 8
		fallthrough
	case 5:
		k2 ^= uint32(tail[4]) << 0
		k2 *= two128x86
		k2 = bits.RotateLeft32(k2, 16)
		k2 *= three128x86
		m.hash2 ^= k2
		fallthrough
	case 4:
		k1 ^= uint32(tail[3]) << 24
		fallthrough
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0]) << 0
		k1 *= one128x86
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= two128x86
		m.hash1 ^= k1
	}

	m.hash1 ^= uint32(m.written)
	m.hash2 ^= uint32(m.written)
	m.hash3 ^= uint32(m.written)
	m.hash4 ^= uint32(m.written)

	m.hash1 += m.hash2
	m.hash1 += m.hash3
	m.hash1 += m.hash4
	m.hash2 += m.hash1
	m.hash3 += m.hash1
	m.hash4 += m.hash1

	m.hash1 = finalMix32(m.hash1)
	m.hash2 = finalMix32(m.hash2)
	m.hash3 = finalMix32(m.hash3)
	m.hash4 = finalMix32(m.hash4)

	m.hash1 += m.hash2
	m.hash1 += m.hash3
	m.hash1 += m.hash4
	m.hash2 += m.hash1
	m.hash3 += m.hash1
	m.hash4 += m.hash1

	sum := make([]byte, sizeBlock128)
	binary.LittleEndian.PutUint32(sum[0:], m.hash1)
	binary.LittleEndian.PutUint32(sum[4:], m.hash2)
	binary.LittleEndian.PutUint32(sum[8:], m.hash3)
	binary.LittleEndian.PutUint32(sum[12:], m.hash4)
	return sum
}

func (m *murmur128x86v3) calculateBlock(bs []byte) {
	tmp := binary.LittleEndian.Uint32(bs[0:])
	tmp *= one128x86
	tmp = bits.RotateLeft32(tmp, 15)
	tmp *= two128x86
	m.hash1 ^= tmp

	m.hash1 = bits.RotateLeft32(m.hash1, 19)
	m.hash1 += m.hash2
	m.hash1 = (m.hash1 * 5) + 0x561ccd1b

	tmp = binary.LittleEndian.Uint32(bs[4:])
	tmp *= two128x86
	tmp = bits.RotateLeft32(tmp, 16)
	tmp *= three128x86
	m.hash2 ^= tmp

	m.hash2 = bits.RotateLeft32(m.hash2, 17)
	m.hash2 += m.hash3
	m.hash2 = (m.hash2 * 5) + 0x0bcaa747

	tmp = binary.LittleEndian.Uint32(bs[8:])
	tmp *= three128x86
	tmp = bits.RotateLeft32(tmp, 17)
	tmp *= four128x86
	m.hash3 ^= tmp

	m.hash3 = bits.RotateLeft32(m.hash3, 15)
	m.hash3 += m.hash4
	m.hash3 = (m.hash3 * 5) + 0x96cd1c35

	tmp = binary.LittleEndian.Uint32(bs[12:])
	tmp *= four128x86
	tmp = bits.RotateLeft32(tmp, 18)
	tmp *= one128x86
	m.hash4 ^= tmp

	m.hash4 = bits.RotateLeft32(m.hash4, 13)
	m.hash4 += m.hash1
	m.hash4 = (m.hash4 * 5) + 0x32ac3b17
}

type murmur32x86v3 struct {
	buffer  [sizeBlock32]byte
	offset  int
	written int

	digest uint32
	seed   uint32
}

func Murmur32x86v3(seed uint32) hash.Hash32 {
	var m murmur32x86v3

	m.seed = seed
	m.Reset()

	return &m
}

func (m *murmur32x86v3) Size() int { return sizeBlock32 }

func (m *murmur32x86v3) BlockSize() int { return sizeBlock32 }

func (m *murmur32x86v3) Write(bs []byte) (int, error) {
	length := len(bs)
	m.written += length
	if m.offset > 0 {
		i := copy(m.buffer[m.offset:], bs)
		m.offset += i
		if m.offset < sizeBlock32 {
			return length, nil
		}
		m.calculateBlock(m.buffer[:])
		bs, m.offset = bs[i:], 0
	}

	var (
		blocks = len(bs)/sizeBlock32
		written int
	)
	for i := 0; i < blocks; i++ {
		m.calculateBlock(bs[i*sizeBlock32:])
		written += sizeBlock32
	}
	if diff := len(bs)-written; diff > 0 {
		m.offset = copy(m.buffer[0:], bs[written:])
	}
	return length, nil
}

func (m *murmur32x86v3) Reset() {
	m.digest = m.seed
	m.offset = 0
	m.written = 0
}

func (m *murmur32x86v3) Sum32() uint32 {
	return binary.LittleEndian.Uint32(m.Sum(nil))
}

func (m *murmur32x86v3) Sum(bs []byte) []byte {
	y := *m
	sum := y.checksum()
	return append(bs, sum...)
}

func (m *murmur32x86v3) checksum() []byte {
	var (
		tail = m.buffer[:m.offset]
		k1   uint32
	)
	switch m.written & 3 {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= one32x86
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= two32x86
		m.digest ^= k1
	}
	m.digest ^= uint32(m.written)
	m.digest = finalMix32(m.digest)

	sum := make([]byte, sizeBlock32)
	binary.LittleEndian.PutUint32(sum, m.digest)
	return sum
}

func (m *murmur32x86v3) calculateBlock(bs []byte) []byte {
	tmp := binary.LittleEndian.Uint32(bs)
	tmp *= one32x86
	tmp = bits.RotateLeft32(tmp, 15)
	tmp *= two32x86

	m.digest ^= tmp
	m.digest = bits.RotateLeft32(m.digest, 13)
	m.digest = (m.digest * 5) + 0xe6546b64
	return nil
}

func finalMix32(k uint32) uint32 {
	k ^= k >> 16
	k *= 0x85ebca6b

	k ^= k >> 13
	k *= 0xc2b2ae35

	k ^= k >> 16
	return k
}

func finalMix64(k uint64) uint64 {
	k ^= k >> 33
	k *= 0xff51afd7ed558ccd

	k ^= k >> 33
	k *= 0xc4ceb9fe1a85ec53

	k ^= k >> 33
	return k
}
