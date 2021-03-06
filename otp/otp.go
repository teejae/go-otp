package otp

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"strconv"
	"time"
)

// One Time Password Generator.
type Generator interface {
	// generate human readable string, like "123456" or "A DOG WALKED ACROSS THE STREET"
	Generate() string
}

type hotpCounter interface {
	next() uint64
}

type hotpGenerator struct {
	counter hotpCounter
	digits  int
	hasher  hash.Hash
}

// HMAC OTP implementation.
// See: http://www.ietf.org/rfc/rfc4226.txt
func NewHOTPGenerator(secretKey []byte, initCounter uint64, digits int) Generator {
	return &hotpGenerator{counter: &hotpCounterImpl{nextCounter: initCounter}, digits: digits, hasher: hmac.NewSHA1(secretKey)}
}

func (g *hotpGenerator) Generate() string {
	hasher := g.hasher
	hasher.Reset()
	defer hasher.Reset()

	counter := g.counter.next()

	binary.Write(hasher, binary.BigEndian, counter)
	hashValue := hasher.Sum()
	truncatedValue := dynamicTruncate(hashValue)
	otpValue := truncatedValue % uint32(pow(10, int64(g.digits)))

	// want a value with a specific number of digits
	return fmt.Sprintf("%0"+strconv.Itoa(g.digits)+"d", otpValue)
}

const (
	DYNAMIC_TRUNCATE_OFFSET_BIT_MASK byte   = 0x0F
	DYNAMIC_TRUNCATE_31_BIT_MASK     uint32 = 0x7FFFFFFF
)

// HOTP's dynamic truncate.
func dynamicTruncate(hashValue []byte) uint32 {
	if len(hashValue) < 20 {
		panic("the starting hash is too short!")
	}

	offsetBits := hashValue[19] & DYNAMIC_TRUNCATE_OFFSET_BIT_MASK
	// 0 <= offset <= 15
	offset := uint8(offsetBits)

	bits := binary.BigEndian.Uint32(hashValue[offset : offset+4])
	truncated := bits & DYNAMIC_TRUNCATE_31_BIT_MASK
	return truncated
}

// Simple counter.
type hotpCounterImpl struct {
	nextCounter uint64
}

func (c *hotpCounterImpl) next() uint64 {
	nextCounter := c.nextCounter
	c.nextCounter++
	return nextCounter
}

const (
	TOTP_DEFAULT_INIT_SECONDS      = 0
	TOTP_DEFAULT_TIME_STEP_SECONDS = 30
)

// Time-based OTP implementation.
// See: http://tools.ietf.org/id/draft-mraihi-totp-timebased-06.txt
func NewTOTPGenerator(secretKey []byte, initSeconds int64, timeStepSeconds uint64, digits int) Generator {
	// use hotpGenerator, with a time-based counter
	return &hotpGenerator{counter: &totpCounter{initSeconds: initSeconds, timeStepSeconds: timeStepSeconds}, digits: digits, hasher: hmac.NewSHA1(secretKey)}
}

func NewDefaultTOTPGenerator(secretKey []byte, digits int) Generator {
	return NewTOTPGenerator(secretKey, TOTP_DEFAULT_INIT_SECONDS, TOTP_DEFAULT_TIME_STEP_SECONDS, digits)
}

type totpCounter struct {
	initSeconds     int64
	timeStepSeconds uint64
}

func (c *totpCounter) next() uint64 {
	diffSeconds := uint64(time.Seconds() - c.initSeconds)
	return diffSeconds / c.timeStepSeconds
}

// Computes base ** exp.
func pow(base, exp int64) int64 {
	product := int64(1)
	for ; exp > 0; exp-- {
		product *= base
	}
	return product
}
