package tm

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"unlock-music.dev/cli/algo/common"
	"unlock-music.dev/cli/internal/sniff"
)

var replaceHeader = []byte{0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70}
var magicHeader = []byte{0x51, 0x51, 0x4D, 0x55} //0x15, 0x1D, 0x1A, 0x21

// tmHeaderSize is how much we read up front. The old code read only 8 bytes
// and handed them to the m4a sniffer, which needs a full 16-byte ftyp box and
// used to panic on shorter input.
const tmHeaderSize = 32

type Decoder struct {
	raw io.ReadSeeker // raw is the original file reader

	offset int
	audio  io.Reader // audio is the decrypted audio data
}

func (d *Decoder) Validate() error {
	header := make([]byte, tmHeaderSize)
	// Read at least the magic header; a short file is fine as long as the bytes
	// we did read are enough for the branches below.
	n, err := io.ReadAtLeast(d.raw, header, len(magicHeader))
	if err != nil {
		return fmt.Errorf("tm read header: %w", err)
	}
	header = header[:n]

	if bytes.Equal(magicHeader, header[:len(magicHeader)]) { // replace m4a header
		if len(header) < len(replaceHeader) {
			return errors.New("tm: file too short")
		}
		// The first 8 bytes are replaced by a fresh ftyp box header; bytes read
		// ahead beyond that are fed back before the rest of the file.
		d.audio = io.MultiReader(
			bytes.NewReader(replaceHeader),
			bytes.NewReader(header[len(replaceHeader):]),
			d.raw,
		)
		return nil
	}

	if _, ok := sniff.AudioExtension(header); ok { // not encrypted
		d.audio = io.MultiReader(bytes.NewReader(header), d.raw)
		return nil
	}

	return errors.New("tm: invalid magic header")
}

func (d *Decoder) Read(buf []byte) (int, error) {
	return d.audio.Read(buf)
}

func NewTmDecoder(p *common.DecoderParams) common.Decoder {
	return &Decoder{raw: p.Reader}
}

func init() {
	// QQ Music IOS M4a (replace header)
	common.RegisterDecoder("tm2", false, NewTmDecoder)
	common.RegisterDecoder("tm6", false, NewTmDecoder)

	// QQ Music IOS Mp3 (not encrypted)
	common.RegisterDecoder("tm0", false, NewTmDecoder)
	common.RegisterDecoder("tm3", false, NewTmDecoder)
}
