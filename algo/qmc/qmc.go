package qmc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"

	"go.uber.org/zap"

	"unlock-music.dev/cli/algo/common"
	"unlock-music.dev/cli/internal/sniff"
)

type Decoder struct {
	raw    io.ReadSeeker // raw is the original file reader
	params *common.DecoderParams

	audio    io.Reader // audio is the encrypted audio data
	audioLen int       // audioLen is the audio data length
	offset   int       // offset is the current audio read position

	decodedKey []byte // decodedKey is the decoded key for cipher
	cipher     common.StreamDecoder

	songID        int
	rawMetaExtra2 int

	albumID      int
	albumMediaID string

	// cache
	meta          common.AudioMeta
	cover         []byte
	embeddedCover bool          // embeddedCover is true if the cover is embedded in the file
	probeBuf      *bytes.Buffer // probeBuf caches the decrypted stream for metadata probing; nil unless needed

	// provider
	logger *zap.Logger
}

// Read implements io.Reader, offer the decrypted audio data.
// Validate should call before Read to check if the file is valid.
func (d *Decoder) Read(p []byte) (int, error) {
	n, err := d.audio.Read(p)
	if n > 0 {
		d.cipher.Decrypt(p[:n], d.offset)
		d.offset += n

		if d.probeBuf != nil {
			_, _ = d.probeBuf.Write(p[:n]) // bytes.Buffer.Write never return error
		}
	}
	return n, err
}

func NewDecoder(p *common.DecoderParams) common.Decoder {
	logger := p.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Decoder{raw: p.Reader, params: p, logger: logger}
}

func NewQmcCipherDecoder(key []byte) (common.StreamDecoder, error) {
	if len(key) > 300 {
		return newRC4Cipher(key)
	} else if len(key) != 0 {
		return newMapCipher(key)
	}
	return newStaticCipher(), nil
}

func NewQmcCipherDecoderFromEKey(ekey []byte) (common.StreamDecoder, error) {
	key, err := deriveKey(ekey)
	if err != nil {
		return nil, err
	}
	return NewQmcCipherDecoder(key)
}

func (d *Decoder) Validate() error {
	footer, err := readFooter(d.raw)
	if err != nil {
		return err
	}
	d.audioLen = int(footer.audioLen)
	d.songID = footer.songID

	key, err := d.resolveKey(footer)
	if err != nil {
		return err
	}
	d.decodedKey = key

	// check cipher type and init decode cipher
	d.cipher, err = NewQmcCipherDecoder(d.decodedKey)
	if err != nil {
		return fmt.Errorf("qmc init cipher: %w", err)
	}

	// test with first 16 bytes
	if err := d.validateDecode(); err != nil {
		return err
	}

	// reset position, limit to audio, prepare for Read
	if _, err := d.raw.Seek(0, io.SeekStart); err != nil {
		return err
	}
	d.audio = io.LimitReader(d.raw, int64(d.audioLen))

	// Metadata probing needs the whole decrypted stream in memory (ffprobe
	// cannot seek on it), so only allocate it when the caller asked for
	// metadata. Without --update-metadata this keeps memory O(1) per file
	// instead of O(file size).
	if d.params.UpdateMetadata {
		d.probeBuf = &bytes.Buffer{}
	}

	return nil
}

// resolveKey follows qmunlock's precedence:
// embedded tail key > manual ekey > local MMKV vault > QQ Music API.
func (d *Decoder) resolveKey(footer *fileFooter) ([]byte, error) {
	if len(footer.ekey) > 0 {
		return deriveKey(footer.ekey)
	}
	if manual := getManualEkey(); manual != "" {
		return deriveKey([]byte(manual))
	}

	// Legacy mac QQ Music stores per-file keys in MMKV. This also initializes
	// the vault (including encrypted 20.x vaults) for the musicEx fallback.
	if runtime.GOOS == "darwin" && d.params.FilePath != "" {
		if key, err := readKeyFromMMKV(d.params.FilePath, d.logger); err == nil {
			return key, nil
		} else {
			d.logger.Debug("mmkv lookup by path failed", zap.Error(err))
		}
	}

	if footer.kind == footerMusicEx {
		if runtime.GOOS == "darwin" && footer.mediaFileName != "" {
			if key, err := readKeyFromMMKVCustom(footer.mediaFileName, d.logger); err == nil {
				return key, nil
			} else {
				d.logger.Debug("mmkv lookup by media filename failed",
					zap.String("filename", footer.mediaFileName), zap.Error(err))
			}
		}
		if isOnlineEkeyAllowed() && footer.mediaID != "" && footer.mediaFileName != "" {
			if key, err := fetchEkey(footer.mediaID, footer.mediaFileName, d.logger); err == nil {
				return key, nil
			} else {
				d.logger.Warn("fetch ekey from QQ Music API failed", zap.Error(err))
			}
		}
		return nil, errors.New("qmc: musicex 文件需要 ekey（已尝试手动 ekey、MMKV 和 QQ 音乐 API）；请登录 QQ 音乐、使用 --qmc-ekey，或在 macOS 上提供 --qmc-mmkv-key")
	}

	if footer.kind == footerStatic {
		return nil, nil
	}
	return nil, errors.New("qmc: no key found for encrypted file")
}

func (d *Decoder) validateDecode() error {
	_, err := d.raw.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("qmc seek to start: %w", err)
	}

	buf := make([]byte, 64)
	if _, err := io.ReadFull(d.raw, buf); err != nil {
		return fmt.Errorf("qmc read header: %w", err)
	}

	d.cipher.Decrypt(buf, 0)
	_, ok := sniff.AudioExtension(buf)
	if !ok {
		return errors.New("qmc: detect file type failed")
	}
	return nil
}

//goland:noinspection SpellCheckingInspection
func init() {
	supportedExts := []string{
		"qmc", "qmc0", "qmc3", // QQ Music MP3
		"qmc2", "qmc4", "qmc6", "qmc8", // QQ Music M4A
		"qmcflac", // QQ Music FLAC
		"qmcogg",  // QQ Music OGG

		"tkm", // QQ Music Accompaniment M4A

		"bkcmp3", "bkcm4a", "bkcflac", "bkcwav", "bkcape", "bkcogg", "bkcwma", // Moo Music

		"666c6163", // QQ Music Weiyun Flac
		"6d7033",   // QQ Music Weiyun Mp3
		"6f6767",   // QQ Music Weiyun Ogg
		"6d3461",   // QQ Music Weiyun M4a
		"776176",   // QQ Music Weiyun Wav

		"mmp4", // QQ Music MP4 Container, tipically used for Dolby EAC3 stream
	}
	for _, ext := range supportedExts {
		common.RegisterDecoder(ext, false, NewDecoder)
	}

	// New ogg/flac:
	extraExtsCanHaveSuffix := []string{"mgg", "mflac"}
	// Mac also adds some extra suffix to ext:
	extraExtSuffix := []string{"0", "1", "a", "h", "l", "m"}
	for _, ext := range extraExtsCanHaveSuffix {
		common.RegisterDecoder(ext, false, NewDecoder)
		for _, suffix := range extraExtSuffix {
			common.RegisterDecoder(ext+suffix, false, NewDecoder)
		}
	}
}
