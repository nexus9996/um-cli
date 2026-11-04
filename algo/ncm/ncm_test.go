package ncm

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"io"
	"testing"

	"go.uber.org/zap"

	"unlock-music.dev/cli/algo/common"
)

func writeU32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

// buildNCM builds a minimal .ncm container without metadata and without a
// cover, carrying the given encrypted audio payload.
func buildNCM(t *testing.T, audioKey, encryptedAudio []byte) []byte {
	t.Helper()

	// key box: "neteasecloudmusic" + key, padded to 128 bytes with the pad
	// length (NCM pads to a fixed overall size, not to the AES block size).
	plain := append([]byte("neteasecloudmusic"), audioKey...)
	plain = append(plain, bytes.Repeat([]byte{byte(128 - len(plain))}, 128-len(plain))...)

	block, err := aes.NewCipher(keyCore)
	if err != nil {
		t.Fatal(err)
	}
	keyBox := make([]byte, len(plain))
	for i := 0; i < len(plain); i += aes.BlockSize {
		block.Encrypt(keyBox[i:i+aes.BlockSize], plain[i:i+aes.BlockSize])
	}
	for i := range keyBox {
		keyBox[i] ^= 0x64
	}

	var buf bytes.Buffer
	buf.WriteString(magicHeader)
	buf.Write([]byte{0, 0}) // 2-byte gap
	writeU32(&buf, uint32(len(keyBox)))
	buf.Write(keyBox)
	writeU32(&buf, 0)          // meta length: no metadata at all
	buf.Write(make([]byte, 5)) // crc32 + flag, skipped by the decoder
	writeU32(&buf, 4)          // cover frame length (length field only)
	writeU32(&buf, 0)          // cover length
	buf.Write(make([]byte, 4)) // bytes skipped by the seek to the audio offset
	buf.Write(encryptedAudio)
	return buf.Bytes()
}

func TestDecodeWithoutMetadata(t *testing.T) {
	audioKey := []byte("0123456789abcdef")
	audioPlain := make([]byte, 256)
	copy(audioPlain, []byte{'I', 'D', '3', 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for i := 16; i < len(audioPlain); i++ {
		audioPlain[i] = byte(i)
	}
	encrypted := make([]byte, len(audioPlain))
	copy(encrypted, audioPlain)
	newNcmCipher(audioKey).Decrypt(encrypted, 0)

	file := buildNCM(t, audioKey, encrypted)
	d := NewDecoder(&common.DecoderParams{Reader: bytes.NewReader(file), Logger: zap.NewNop()})
	if err := d.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	out, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, audioPlain) {
		t.Fatal("decoded audio does not match the plaintext")
	}
}

// A key length that is not AES block aligned used to panic inside
// utils.DecryptAES128ECB; it must be reported as an error instead.
func TestInvalidKeyLengthIsErrorNotPanic(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(magicHeader)
	buf.Write([]byte{0, 0})
	writeU32(&buf, 20) // not a multiple of 16
	buf.Write(make([]byte, 20))

	d := NewDecoder(&common.DecoderParams{Reader: bytes.NewReader(buf.Bytes()), Logger: zap.NewNop()})
	if err := d.Validate(); err == nil {
		t.Fatal("expected an error for an invalid key length")
	}
}
