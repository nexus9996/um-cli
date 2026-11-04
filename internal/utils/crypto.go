package utils

import (
	"crypto/aes"
	"errors"
	"fmt"
)

// ErrInvalidPadding is returned when a buffer does not carry a usable PKCS#7
// padding trailer.
var ErrInvalidPadding = errors.New("invalid PKCS#7 padding")

// PKCS7UnPadding removes the padding from a decrypted buffer.
//
// It intentionally does not enforce a pad length <= AES block size: NCM pads
// its key box up to a fixed overall size, so the trailing length byte can be
// larger than 16. It never panics though — an empty buffer, a zero length or a
// length larger than the buffer is reported as ErrInvalidPadding instead of
// slicing out of range.
func PKCS7UnPadding(encrypt []byte) ([]byte, error) {
	if len(encrypt) == 0 {
		return nil, ErrInvalidPadding
	}
	unPadding := int(encrypt[len(encrypt)-1])
	if unPadding == 0 || unPadding > len(encrypt) {
		return nil, ErrInvalidPadding
	}
	return encrypt[:len(encrypt)-unPadding], nil
}

// DecryptAES128ECB decrypts data with AES-128 in ECB mode (padding is kept).
// The key must be 16 bytes and the payload a multiple of the AES block size;
// both are validated up front so malformed input yields an error, not a panic.
func DecryptAES128ECB(data, key []byte) ([]byte, error) {
	if len(key) != aes.BlockSize {
		return nil, fmt.Errorf("invalid AES-128 key size: %d", len(key))
	}
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid AES-ECB payload size: %d", len(data))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(data))
	for bs := 0; bs < len(data); bs += aes.BlockSize {
		block.Decrypt(decrypted[bs:bs+aes.BlockSize], data[bs:bs+aes.BlockSize])
	}
	return decrypted, nil
}
