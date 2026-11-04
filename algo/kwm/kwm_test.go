package kwm

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func newTestFile(bitrateField string) []byte {
	header := make([]byte, 0x400)
	copy(header, magicHeader1)
	binary.LittleEndian.PutUint64(header[0x18:0x20], 123456)
	copy(header[0x30:0x38], bitrateField)
	return append(header, bytes.Repeat([]byte{0xAA}, 128)...)
}

func TestValidateValidHeader(t *testing.T) {
	d := &Decoder{rd: bytes.NewReader(newTestFile("320mp3"))}
	if err := d.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if d.bitrate != 320 || d.outputExt != "mp3" {
		t.Fatalf("unexpected header parse: bitrate=%d ext=%q", d.bitrate, d.outputExt)
	}
}

// parseBitrateAndType used to slice with sep == -1 for an all-NUL field.
func TestValidateEmptyBitrateField(t *testing.T) {
	d := &Decoder{rd: bytes.NewReader(newTestFile(""))}
	if err := d.Validate(); err == nil {
		t.Fatal("expected an error for an empty bitrate/ext field")
	}
}
