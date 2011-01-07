package otp

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"strconv"
)

type Generator interface {
	// generate human readable string
	Generate() string
}

type HOTPCounter uint64
type HOTPGenerator struct {
	counter HOTPCounter
	digits int
	hasher hash.Hash
}

func NewHOTPGenerator(secretKey []byte, initCounter HOTPCounter, digits int) *HOTPGenerator {
	return &HOTPGenerator{counter: initCounter, digits: digits, hasher: hmac.NewSHA1(secretKey)}
}

func (g *HOTPGenerator) Generate() string {
	hasher := g.hasher
	hasher.Reset()
	defer hasher.Reset()
	
	binary.Write(hasher, binary.BigEndian, g.counter)
	hashValue := hasher.Sum()
	truncatedValue := dynamicTruncate(hashValue)
	otpValue := truncatedValue % uint32((10 ^ g.digits))
	
	// increment counter
	g.counter++
	
	return strconv.Uitoa64(uint64(otpValue))
}

const (
	DYNAMIC_TRUNCATE_OFFSET_BIT_MASK byte = 0x0F
	DYNAMIC_TRUNCATE_31_BIT_MASK uint32 = 0x7FFFFFFF
)

func dynamicTruncate(hashValue []byte) uint32 {
	if len(hashValue) < 20 {
		panic("the generated hash is too short!")
	}
	
	offsetBits := hashValue[19] & DYNAMIC_TRUNCATE_OFFSET_BIT_MASK
	// 0 <= offset <= 15
	offset := uint8(offsetBits)
	
	p := binary.BigEndian.Uint32(hashValue[offset:offset + 4])
	return p & DYNAMIC_TRUNCATE_31_BIT_MASK
}