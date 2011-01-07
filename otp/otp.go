package otp

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"strconv"
)

// One Time Password Generator.
type Generator interface {
	// generate human readable string, like "123456" or "A DOG WALKED ACROSS THE STREET"
	Generate() string
}

// HMAC OTP implementation.
// See: http://www.ietf.org/rfc/rfc4226.txt
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
	otpValue := truncatedValue % uint32(pow(10, int64(g.digits)))
	
	// increment counter
	g.counter++
	
	// want a value with a specific number of digits
	return fmt.Sprintf("%0" + strconv.Itoa(g.digits) + "d", otpValue)
}

const (
	DYNAMIC_TRUNCATE_OFFSET_BIT_MASK byte = 0x0F
	DYNAMIC_TRUNCATE_31_BIT_MASK uint32 = 0x7FFFFFFF
)

// HOTP's dynamic truncate.
func dynamicTruncate(hashValue []byte) uint32 {
	if len(hashValue) < 20 {
		panic("the starting hash is too short!")
	}
	
	offsetBits := hashValue[19] & DYNAMIC_TRUNCATE_OFFSET_BIT_MASK
	// 0 <= offset <= 15
	offset := uint8(offsetBits)

	bits := binary.BigEndian.Uint32(hashValue[offset:offset + 4])
	truncated := bits & DYNAMIC_TRUNCATE_31_BIT_MASK
	return truncated
}

// Computes base ** exp.
func pow(base, exp int64) int64 {
	product := int64(1)
	for ; exp > 0; exp-- {
		product *= base
	}
	return product
}
