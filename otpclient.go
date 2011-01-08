package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"otp"
)

const (
	DIGITS       = 6
	INIT_COUNTER = 141215332523
	INIT_SECONDS = 0
	TIME_STEP    = 1
)

var (
	keyFile    = flag.String("keyFile", "", "key file with shared secret data")
	numEntries = flag.Int("numEntries", 1, "number of hashes to generate")
	useTime    = flag.Bool("useTime", false, "use time-based OTP instead of hmac OTP")
)

func main() {
	flag.Parse()

	if *keyFile == "" {
		log.Println("need keyFile")
		return
	}

	f, err := os.Open(*keyFile, os.O_RDONLY, 0)
	if err != nil {
		log.Println("could not find keyfile")
		return
	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	buf.ReadFrom(f)

	var hotp otp.Generator
	if *useTime {
		hotp = otp.NewTOTPGenerator(buf.Bytes(), INIT_SECONDS, TIME_STEP, DIGITS)
	} else {
		hotp = otp.NewHOTPGenerator(buf.Bytes(), INIT_COUNTER, DIGITS)
	}
	for i := 0; i < *numEntries; i++ {
		log.Println(hotp.Generate())
	}
}
