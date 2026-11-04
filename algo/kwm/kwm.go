package kwm

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"

	"unlock-music.dev/cli/algo/common"
)

const magicHeader1 = "yeelion-kuwo-tme"
const magicHeader2 = "yeelion-kuwo\x00\x00\x00\x00"
const keyPreDefined = "MoOtOiTvINGwd2E6n0E1i7L5t2IoOoNk"

type Decoder struct {
	rd io.ReadSeeker

	cipher common.StreamDecoder
	offset int

	outputExt string
	bitrate   int
}

func (d *Decoder) GetAudioExt() string {
	return "." + d.outputExt
}

func NewDecoder(p *common.DecoderParams) common.Decoder {
	return &Decoder{rd: p.Reader}
}

// Validate checks if the file is a valid Kuwo .kw file.
// rd will be seeked to the beginning of the encrypted audio.
func (d *Decoder) Validate() error {
	header := make([]byte, 0x400) // kwm header is fixed to 1024 bytes
	_, err := io.ReadFull(d.rd, header)
	if err != nil {
		return fmt.Errorf("kwm read header: %w", err)
	}

	// check magic header, 0x00 - 0x0F
	magicHeader := header[:0x10]
	if !bytes.Equal([]byte(magicHeader1), magicHeader) &&
		!bytes.Equal([]byte(magicHeader2), magicHeader) {
		return errors.New("kwm magic header not matched")
	}

	d.cipher = newKwmCipher(header[0x18:0x20]) // Crypto Key, 0x18 - 0x1F

	bitrate, outputExt, err := parseBitrateAndType(header[0x30:0x38]) // Bitrate & File Extension, 0x30 - 0x38
	if err != nil {
		return err
	}
	d.bitrate, d.outputExt = bitrate, outputExt

	return nil
}

// parseBitrateAndType parses the "320mp3"-style header field. It returns an
// error instead of panicking when the field is empty or malformed (the old
// code sliced with sep == -1 and crashed on an all-NUL field).
func parseBitrateAndType(header []byte) (int, string, error) {
	tmp := strings.TrimRight(string(header), "\x00")
	if tmp == "" {
		return 0, "", errors.New("kwm: empty bitrate/ext header")
	}
	sep := strings.IndexFunc(tmp, func(r rune) bool {
		return !unicode.IsDigit(r)
	})
	if sep <= 0 {
		return 0, "", fmt.Errorf("kwm: invalid bitrate/ext header %q", tmp)
	}

	bitrate, err := strconv.Atoi(tmp[:sep])
	if err != nil {
		return 0, "", fmt.Errorf("kwm: invalid bitrate %q: %w", tmp[:sep], err)
	}
	outputExt := strings.ToLower(strings.TrimSpace(tmp[sep:]))
	if outputExt == "" {
		return 0, "", fmt.Errorf("kwm: missing audio extension in header %q", tmp)
	}
	return bitrate, outputExt, nil
}

func (d *Decoder) Read(b []byte) (int, error) {
	n, err := d.rd.Read(b)
	if n > 0 {
		d.cipher.Decrypt(b[:n], d.offset)
		d.offset += n
	}
	return n, err
}

func padOrTruncate(raw string, length int) string {
	lenRaw := len(raw)
	out := raw
	if lenRaw == 0 {
		out = string(make([]byte, length))
	} else if lenRaw > length {
		out = raw[:length]
	} else if lenRaw < length {
		_tmp := make([]byte, 32)
		for i := 0; i < 32; i++ {
			_tmp[i] = raw[i%lenRaw]
		}
		out = string(_tmp)
	}
	return out
}

func init() {
	// Kuwo Mp3/Flac
	common.RegisterDecoder("kwm", false, NewDecoder)
	common.RegisterDecoder("kwm", false, common.NewRawDecoder)
}
