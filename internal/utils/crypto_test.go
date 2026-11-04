package utils

import (
	"bytes"
	"testing"
)

// PKCS7UnPadding used to slice with a negative length on malformed input.
func TestPKCS7UnPaddingNeverPanics(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x00},
		{0x10},
		bytes.Repeat([]byte{0xFF}, 8),
		bytes.Repeat([]byte{0x05}, 16),
	}
	for _, in := range cases {
		_, _ = PKCS7UnPadding(in) // must not panic
	}
}

func TestPKCS7UnPadding(t *testing.T) {
	in := append([]byte("hello"), bytes.Repeat([]byte{0x0b}, 11)...) // 16 bytes
	out, err := PKCS7UnPadding(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "hello" {
		t.Fatalf("got %q, want %q", out, "hello")
	}

	if _, err := PKCS7UnPadding([]byte{1, 2, 0x05}); err != ErrInvalidPadding {
		t.Fatalf("expected ErrInvalidPadding, got %v", err)
	}
}

// DecryptAES128ECB used to ignore aes.NewCipher errors and slice out of range.
func TestDecryptAES128ECBValidation(t *testing.T) {
	key := make([]byte, 16)
	if _, err := DecryptAES128ECB(make([]byte, 16), make([]byte, 15)); err == nil {
		t.Fatal("expected error for a non-16-byte key")
	}
	if _, err := DecryptAES128ECB(make([]byte, 17), key); err == nil {
		t.Fatal("expected error for a payload that is not block aligned")
	}
	if _, err := DecryptAES128ECB(nil, key); err == nil {
		t.Fatal("expected error for an empty payload")
	}
}
