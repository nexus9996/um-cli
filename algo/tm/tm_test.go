package tm

import (
	"bytes"
	"io"
	"testing"

	"unlock-music.dev/cli/algo/common"
)

var m4aHeader = []byte{
	0x00, 0x00, 0x00, 0x20, 'f', 't', 'y', 'p',
	'M', '4', 'A', ' ', 0x00, 0x00, 0x00, 0x00,
	'M', '4', 'A', ' ', 'm', 'p', '4', '2',
}

// The decoder used to read exactly 8 bytes and hand them to the m4a sniffer,
// which panicked while parsing a full ftyp box (a plain .m4a renamed .tm2).
func TestPlainM4ADoesNotPanic(t *testing.T) {
	data := append(append([]byte{}, m4aHeader...), bytes.Repeat([]byte{0xAA}, 64)...)
	d := NewTmDecoder(&common.DecoderParams{Reader: bytes.NewReader(data)})
	if err := d.Validate(); err != nil {
		t.Fatalf("plain m4a should be passed through, got: %v", err)
	}
	out, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, data) {
		t.Fatal("passthrough changed the payload")
	}
}

func TestReplaceHeader(t *testing.T) {
	original := append(append([]byte{}, m4aHeader...), bytes.Repeat([]byte{0xBB}, 64)...)
	encrypted := append([]byte("QQMU"), []byte{0x15, 0x1D, 0x1A, 0x21}...)
	encrypted = append(encrypted, original[8:]...)

	d := NewTmDecoder(&common.DecoderParams{Reader: bytes.NewReader(encrypted)})
	if err := d.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	out, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, original) {
		t.Fatalf("decoded payload mismatch: got %x want %x", out[:16], original[:16])
	}
}

func TestShortFileIsRejected(t *testing.T) {
	d := NewTmDecoder(&common.DecoderParams{Reader: bytes.NewReader([]byte("QQM"))})
	if err := d.Validate(); err == nil {
		t.Fatal("expected an error for a truncated file")
	}
}
