package qmc

import (
	"math/rand"
	"testing"
)

// decryptTencentTea computed outLen = len - 1 - padLen - 2 - 7; for a 16-byte
// input with padLen=7 that is -1 and make([]byte, outLen) panicked.
func TestDecryptTencentTeaNeverPanics(t *testing.T) {
	key := []byte("0123456789abcdef")
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 512; i++ {
		buf := make([]byte, 16)
		for j := range buf {
			buf[j] = byte(rnd.Intn(256))
		}
		_, _ = decryptTencentTea(buf, key) // must not panic whatever the padding header says
	}
}

// A 24-byte EncV1 ekey reaches decryptTencentTea with a 16-byte body and used
// to crash the whole CLI through deriveKey; it must not panic now.
func TestDeriveKeyShortEncV1DoesNotPanic(t *testing.T) {
	const ekey = "EH534yWAKXS4g9iOAk0SxNFSOCx7NDMK"
	if _, err := deriveKey([]byte(ekey)); err != nil {
		t.Logf("deriveKey rejected the truncated ekey (fine): %v", err)
	}
}
