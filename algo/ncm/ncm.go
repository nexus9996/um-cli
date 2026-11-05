package ncm

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net/http"
	"strings"

	"unlock-music.dev/cli/algo/common"
	"unlock-music.dev/cli/internal/sniff"
	"unlock-music.dev/cli/internal/utils"
)

const magicHeader = "CTENFDAM"

// Sanity limits for the length fields read straight from the file. They are
// far above any real value but keep a forged header from triggering a
// multi-gigabyte allocation.
const (
	maxKeyLen   = 1 << 20  // 1 MiB
	maxMetaLen  = 16 << 20 // 16 MiB
	maxCoverLen = 64 << 20 // 64 MiB
)

var (
	keyCore = []byte{
		0x68, 0x7a, 0x48, 0x52, 0x41, 0x6d, 0x73, 0x6f,
		0x35, 0x6b, 0x49, 0x6e, 0x62, 0x61, 0x78, 0x57,
	}
	keyMeta = []byte{
		0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21,
		0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28,
	}
)

func NewDecoder(p *common.DecoderParams) common.Decoder {
	return &Decoder{rd: p.Reader, logger: p.Logger.With(zap.String("module", "ncm"))}
}

type Decoder struct {
	logger   *zap.Logger
	rd       io.ReadSeeker // rd is the original file reader
	fileSize int64

	offset int
	cipher common.StreamDecoder

	metaRaw  []byte
	metaType string
	meta     ncmMeta
	cover    []byte
}

// Validate checks if the file is a valid Netease .ncm file.
// rd will be seeked to the beginning of the encrypted audio.
func (d *Decoder) Validate() error {
	fileSize, err := d.rd.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("ncm seek end: %w", err)
	}
	d.fileSize = fileSize
	if _, err := d.rd.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("ncm seek start: %w", err)
	}

	if err := d.validateMagicHeader(); err != nil {
		return err
	}

	if _, err := d.rd.Seek(2, io.SeekCurrent); err != nil { // 2 bytes gap
		return fmt.Errorf("ncm seek file: %w", err)
	}

	keyData, err := d.readKeyData()
	if err != nil {
		return err
	}

	if err := d.readMetaData(); err != nil {
		return fmt.Errorf("ncm read meta data: %w", err)
	}

	if _, err := d.rd.Seek(5, io.SeekCurrent); err != nil { // 5 bytes gap
		return fmt.Errorf("ncm seek gap: %w", err)
	}

	if err := d.readCoverData(); err != nil {
		return fmt.Errorf("parse ncm cover file failed: %w", err)
	}

	if err := d.parseMeta(); err != nil {
		// Do not dump the whole JSON into the log/error; it can be megabytes.
		return fmt.Errorf("parse meta failed: %w (raw json=%.256s)", err, string(d.metaRaw))
	}

	d.cipher = newNcmCipher(keyData)

	// Cheap integrity check: decrypt the first block and look for a known audio
	// magic number. A tampered key box produces garbage here instead of a
	// silently "successful" conversion.
	audioStart, err := d.rd.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("ncm fetch audio offset: %w", err)
	}
	probe := make([]byte, 64)
	if _, err := io.ReadFull(d.rd, probe); err != nil {
		return fmt.Errorf("ncm detect audio type: %w", err)
	}
	d.cipher.Decrypt(probe, 0)
	if _, ok := sniff.AudioExtension(probe); !ok {
		d.logger.Warn("ncm audio header is not a known format; " +
			"the key box or metadata may be corrupt (decoded audio will likely be garbage)")
	}
	if _, err := d.rd.Seek(audioStart, io.SeekStart); err != nil {
		return fmt.Errorf("ncm seek audio start: %w", err)
	}

	return nil
}

func (d *Decoder) validateMagicHeader() error {
	header := make([]byte, len(magicHeader)) // 0x00 - 0x07
	if _, err := d.rd.Read(header); err != nil {
		return fmt.Errorf("ncm read magic header: %w", err)
	}

	if !bytes.Equal([]byte(magicHeader), header) {
		return errors.New("ncm magic header not match")
	}

	return nil
}

func (d *Decoder) readKeyData() ([]byte, error) {
	bKeyLen := make([]byte, 4) //
	if _, err := io.ReadFull(d.rd, bKeyLen); err != nil {
		return nil, fmt.Errorf("ncm read key length: %w", err)
	}
	iKeyLen := binary.LittleEndian.Uint32(bKeyLen)
	if iKeyLen == 0 || iKeyLen > maxKeyLen || iKeyLen%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ncm invalid key length: %d", iKeyLen)
	}

	bKeyRaw := make([]byte, iKeyLen)
	if _, err := io.ReadFull(d.rd, bKeyRaw); err != nil {
		return nil, fmt.Errorf("ncm read key data: %w", err)
	}
	for i := uint32(0); i < iKeyLen; i++ {
		bKeyRaw[i] ^= 0x64
	}

	keyBox, err := utils.DecryptAES128ECB(bKeyRaw, keyCore)
	if err != nil {
		return nil, fmt.Errorf("ncm decrypt key data: %w", err)
	}
	keyData, err := utils.PKCS7UnPadding(keyBox)
	if err != nil {
		return nil, fmt.Errorf("ncm unpad key data: %w", err)
	}
	if len(keyData) < 17 {
		return nil, fmt.Errorf("ncm key data too short: %d", len(keyData))
	}

	return keyData[17:], nil
}

func (d *Decoder) readMetaData() error {
	bMetaLen := make([]byte, 4) //
	if _, err := io.ReadFull(d.rd, bMetaLen); err != nil {
		return fmt.Errorf("ncm read meta length: %w", err)
	}
	iMetaLen := binary.LittleEndian.Uint32(bMetaLen)

	if iMetaLen == 0 {
		return nil // no meta data
	}
	const metaPrefixLen = 22 // len("163 key(Don't modify):")
	if iMetaLen <= metaPrefixLen || iMetaLen > maxMetaLen {
		return fmt.Errorf("ncm invalid meta length: %d", iMetaLen)
	}

	bMetaRaw := make([]byte, iMetaLen)
	if _, err := io.ReadFull(d.rd, bMetaRaw); err != nil {
		return fmt.Errorf("ncm read meta data: %w", err)
	}
	bMetaRaw = bMetaRaw[metaPrefixLen:] // skip "163 key(Don't modify):"
	for i := 0; i < len(bMetaRaw); i++ {
		bMetaRaw[i] ^= 0x63
	}

	cipherText, err := base64.StdEncoding.DecodeString(string(bMetaRaw))
	if err != nil {
		return errors.New("decode ncm meta failed: " + err.Error())
	}
	metaPlain, err := utils.DecryptAES128ECB(cipherText, keyMeta)
	if err != nil {
		return fmt.Errorf("ncm decrypt meta: %w", err)
	}
	metaRaw, err := utils.PKCS7UnPadding(metaPlain)
	if err != nil {
		return fmt.Errorf("ncm unpad meta: %w", err)
	}
	sep := bytes.IndexByte(metaRaw, ':')
	if sep == -1 {
		return errors.New("invalid ncm meta file")
	}

	d.metaType = string(metaRaw[:sep])
	d.metaRaw = metaRaw[sep+1:]

	return nil
}

func (d *Decoder) readCoverData() error {
	bCoverFrameLen := make([]byte, 4)
	if _, err := io.ReadFull(d.rd, bCoverFrameLen); err != nil {
		return fmt.Errorf("ncm read cover length: %w", err)
	}

	coverFrameStartOffset, err := d.rd.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("ncm fetch cover frame start offset: %w", err)
	}
	coverFrameLen := binary.LittleEndian.Uint32(bCoverFrameLen)

	bCoverLen := make([]byte, 4)
	if _, err := io.ReadFull(d.rd, bCoverLen); err != nil {
		return fmt.Errorf("ncm read cover length: %w", err)
	}
	iCoverLen := binary.LittleEndian.Uint32(bCoverLen)

	if iCoverLen > maxCoverLen {
		return fmt.Errorf("ncm cover too large: %d", iCoverLen)
	}
	// NetEase clients write coverFrameLen == iCoverLen (the frame is this
	// second length field plus the image, and the "+4" below accounts for the
	// field itself), so anything shorter than the image means the header is
	// corrupt and the audio offset would land inside the cover.
	if coverFrameLen < iCoverLen {
		return fmt.Errorf("ncm invalid cover frame: frame=%d cover=%d", coverFrameLen, iCoverLen)
	}

	coverBuf := make([]byte, iCoverLen)
	if _, err := io.ReadFull(d.rd, coverBuf); err != nil {
		return fmt.Errorf("ncm read cover data: %w", err)
	}
	if len(coverBuf) > 0 {
		d.cover = coverBuf
	}

	// Audio starts right after the image; derive the offset from what was
	// actually read instead of trusting coverFrameLen, which is only equal to
	// iCoverLen in practice.
	offsetAudioData := coverFrameStartOffset + 4 + int64(iCoverLen)
	if offsetAudioData < 0 || offsetAudioData > d.fileSize {
		return fmt.Errorf("ncm invalid audio offset: %d (file size %d)", offsetAudioData, d.fileSize)
	}
	_, err = d.rd.Seek(offsetAudioData, io.SeekStart)

	return err
}

func (d *Decoder) parseMeta() error {
	if d.metaType == "" && len(d.metaRaw) == 0 {
		return nil // a file without metadata block is still a valid container
	}
	switch d.metaType {
	case "music":
		d.meta = newNcmMetaMusic(d.logger)
		return json.Unmarshal(d.metaRaw, d.meta)
	case "dj":
		d.meta = new(ncmMetaDJ)
		return json.Unmarshal(d.metaRaw, d.meta)
	default:
		return errors.New("unknown ncm meta type: " + d.metaType)
	}
}

func (d *Decoder) Read(buf []byte) (int, error) {
	n, err := d.rd.Read(buf)
	if n > 0 {
		d.cipher.Decrypt(buf[:n], d.offset)
		d.offset += n
	}
	return n, err
}

func (d *Decoder) GetAudioExt() string {
	if d.meta != nil {
		if format := d.meta.GetFormat(); format != "" {
			return "." + d.meta.GetFormat()
		}
	}
	return ""
}

func (d *Decoder) GetCoverImage(ctx context.Context) ([]byte, error) {
	if len(d.cover) > 0 {
		return d.cover, nil
	}

	if d.meta == nil {
		return nil, errors.New("ncm meta not found")
	}
	imgURL := d.meta.GetAlbumImageURL()
	if !strings.HasPrefix(imgURL, "http") {
		return nil, nil // no cover image
	}

	// fetch cover image
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imgURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ncm download image failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ncm download image failed: unexpected http status %s", resp.Status)
	}
	d.cover, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ncm download image failed: %w", err)
	}

	return d.cover, nil
}

func (d *Decoder) GetAudioMeta(_ context.Context) (common.AudioMeta, error) {
	return d.meta, nil
}

func init() {
	// Netease Mp3/Flac
	common.RegisterDecoder("ncm", false, NewDecoder)
}
