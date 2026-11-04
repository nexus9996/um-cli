package sniff

import "testing"

// 24-byte m4a ftyp header (major brand "M4A ").
var m4aTestHeader = []byte{
	0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p',
	'M', '4', 'A', ' ', 0x00, 0x00, 0x00, 0x00,
	'M', '4', 'A', ' ', 'm', 'p', '4', '2',
}

// AudioExtension used to iterate a map, so an m4a header matching both the
// .m4a and .mp4 sniffers returned a random extension on every call.
func TestAudioExtensionIsDeterministic(t *testing.T) {
	ext, ok := AudioExtension(m4aTestHeader)
	if !ok {
		t.Fatal("m4a header was not detected")
	}
	if ext != ".m4a" {
		t.Fatalf("expected .m4a (specific before fallback), got %q", ext)
	}
	for i := 0; i < 200; i++ {
		got, ok := AudioExtension(m4aTestHeader)
		if !ok || got != ext {
			t.Fatalf("non-deterministic result on iteration %d: %q (ok=%v)", i, got, ok)
		}
	}
}

// readMpeg4FtypBox used to slice header[8:12] after only checking len >= 8,
// which panicked for the 8-byte header the tm decoder passed in.
func TestAudioExtensionShortFtypDoesNotPanic(t *testing.T) {
	for n := 0; n < 16; n++ {
		header := make([]byte, n)
		if n >= 8 {
			copy(header[4:8], "ftyp")
		}
		if _, ok := AudioExtension(header); ok {
			t.Fatalf("a %d-byte header was unexpectedly identified", n)
		}
	}
}
