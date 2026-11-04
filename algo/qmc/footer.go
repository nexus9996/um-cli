package qmc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type footerKind int

const (
	footerStatic footerKind = iota
	footerLegacyEKey
	footerQTag
	footerMusicEx
)

const (
	maxLegacyEkeyLen = 0x500
	footerWindowSize = 4096
)

type fileFooter struct {
	kind          footerKind
	audioLen      int64
	ekey          []byte // base64 text from the file tail
	songID        int
	mediaID       string
	mediaFileName string
}

// readFooter identifies the QMC container from the file tail. It mirrors the
// qmunlock chain: musicex / QTag / STag / legacy ekey / QMCv1 static.
func readFooter(r io.ReadSeeker) (*fileFooter, error) {
	size, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("qmc: seek end: %w", err)
	}
	if size < 8 {
		return nil, errors.New("qmc: file too small")
	}

	tail, err := readLast(r, min64(size, footerWindowSize))
	if err != nil {
		return nil, err
	}
	if bytes.HasSuffix(tail, []byte("STag")) {
		return nil, errors.New("qmc: STag 尾部没有写入密钥，也没有取回通道；请更换来源或使用旧版客户端重新下载")
	}
	if bytes.HasSuffix(tail, []byte("QTag")) {
		return parseQTagFooter(r, size)
	}
	if bytes.HasSuffix(tail, []byte("musicex\x00")) {
		return parseMusicExFooter(r, size, tail)
	}

	keyLen := int64(binary.LittleEndian.Uint32(tail[len(tail)-4:]))
	if keyLen >= 8 && keyLen <= maxLegacyEkeyLen && keyLen+4 <= size {
		end := int64(len(tail)) - 4
		start := end - keyLen
		var rawKey []byte
		if start >= 0 {
			rawKey = tail[start:end]
		}
		rawKey = bytes.TrimRight(rawKey, "\x00")
		if isBase64Text(rawKey) {
			return &fileFooter{
				kind:     footerLegacyEKey,
				audioLen: size - keyLen - 4,
				ekey:     rawKey,
			}, nil
		}
	}

	return &fileFooter{kind: footerStatic, audioLen: size}, nil
}

// QTag layout: "<ekey>,<resource id>[,<version>]" + big-endian size + "QTag".
func parseQTagFooter(r io.ReadSeeker, size int64) (*fileFooter, error) {
	trailer, err := readLast(r, min64(size, 8))
	if err != nil {
		return nil, err
	}
	metaLen := int64(binary.BigEndian.Uint32(trailer[0:4]))
	if metaLen <= 0 || metaLen+8 > size {
		return nil, fmt.Errorf("qmc: invalid QTag metadata length %d", metaLen)
	}
	if _, err := r.Seek(size-8-metaLen, io.SeekStart); err != nil {
		return nil, err
	}
	meta := make([]byte, metaLen)
	if _, err := io.ReadFull(r, meta); err != nil {
		return nil, fmt.Errorf("qmc: read QTag metadata: %w", err)
	}
	items := bytes.Split(meta, []byte(","))
	ekey := items[0]
	if !isBase64Text(ekey) {
		return nil, errors.New("qmc: QTag ekey is not base64")
	}
	songID := 0
	if len(items) >= 2 {
		if id, err := strconv.Atoi(string(items[1])); err == nil && id > 0 && id < 1_000_000_000 {
			songID = id
		}
	}
	return &fileFooter{
		kind:     footerQTag,
		audioLen: size - metaLen - 8,
		ekey:     bytes.TrimRight(ekey, "\x00"),
		songID:   songID,
	}, nil
}

// musicex layout is either:
//   - 192-byte total tail (old clients): 176-byte body + 16-byte trailer
//   - 208-byte total tail (some 20.x builds): 192-byte body + 16-byte trailer
//
// Instead of trusting the size field, locate the UTF-16 media filename and use
// its fixed 0x48 offset to derive the real audio boundary.
func parseMusicExFooter(r io.ReadSeeker, size int64, tail []byte) (*fileFooter, error) {
	if len(tail) < 16 {
		return nil, errors.New("qmc: musicex footer too small")
	}
	trailer := tail[len(tail)-16:]
	tagSize := int64(binary.LittleEndian.Uint32(trailer[0:4]))
	version := binary.LittleEndian.Uint32(trailer[4:8])
	if tagSize < 16 || tagSize > size {
		return nil, fmt.Errorf("qmc: invalid musicex tag size %d", tagSize)
	}
	if version == 0 {
		return nil, fmt.Errorf("qmc: unsupported musicex tag version %d", version)
	}

	windowSize := max64(tagSize+32, footerWindowSize)
	windowSize = min64(windowSize, size)
	window, err := readLast(r, windowSize)
	if err != nil {
		return nil, err
	}
	windowStart := size - int64(len(window))

	mid, midPos := findUTF16Field(window, isMusicID)
	filename, filePos := findUTF16Field(window, isMusicFileName)
	var bodyStart int64 = -1
	if filePos >= 0x48 {
		bodyStart = int64(filePos) - 0x48
	} else if midPos >= 0x0c {
		bodyStart = int64(midPos) - 0x0c
	}
	if bodyStart >= 0 && bodyStart < int64(len(window)) {
		// Some QQ Music 20.x builds prepend a 0x14-byte header before the old
		// struct. If a full pair of fields exists 0x14 bytes earlier, that is
		// the real container start and must be stripped as well.
		structStartAbs := windowStart + bodyStart
		shiftedAbs := structStartAbs - 0x14
		if shiftedMid, shiftedFile, ok := musicFieldsAt(window, int(bodyStart-0x14)); ok {
			bodyStart -= 0x14
			mid, filename = shiftedMid, shiftedFile
		} else if shiftedAbs == size-tagSize || shiftedAbs == size-tagSize-16 {
			// The struct itself sits 0x14 bytes into the footer body. Match the
			// trailer size against either known interpretation before stripping.
			bodyStart -= 0x14
		} else {
			if mid == "" {
				mid, _ = readUTF16Field(window, int(bodyStart+0x0c), 60)
			}
			if filename == "" {
				filename, _ = readUTF16Field(window, int(bodyStart+0x48), 100)
			}
		}
		// The musicex body does not expose a reliable song ID (the first words
		// are audio/metadata, not the old QTag resource id). Keep it zero so
		// metadata falls back to embedded tags / search instead of a wrong song.
		return &fileFooter{
			kind:          footerMusicEx,
			audioLen:      windowStart + bodyStart,
			mediaID:       mid,
			mediaFileName: filename,
		}, nil
	}

	// No recognizable UTF-16 fields: keep the qmunlock interpretation
	// (size includes the trailer) and let key lookup fail with a clear error.
	return &fileFooter{
		kind:     footerMusicEx,
		audioLen: size - tagSize,
	}, nil
}

func musicFieldsAt(window []byte, start int) (string, string, bool) {
	if start < 0 || start+0x48 >= len(window) {
		return "", "", false
	}
	mid, _ := readUTF16Field(window, start+0x0c, 60)
	filename, _ := readUTF16Field(window, start+0x48, 100)
	if !isMusicID(mid) || !isMusicFileName(filename) {
		return "", "", false
	}
	return mid, filename, true
}

func findUTF16Field(window []byte, match func(string) bool) (string, int) {
	for i := 0; i+1 < len(window); i++ {
		if window[i+1] != 0 {
			continue
		}
		text, end := readUTF16Field(window, i, 160)
		if end <= i || !match(text) {
			continue
		}
		return text, i
	}
	return "", -1
}

func readUTF16Field(window []byte, start, maxLen int) (string, int) {
	var builder strings.Builder
	i := start
	for i+1 < len(window) && i-start < maxLen {
		if window[i+1] != 0 {
			break
		}
		c := window[i]
		if c == 0 {
			break
		}
		if c < 0x20 || c > 0x7e {
			break
		}
		builder.WriteByte(c)
		i += 2
	}
	return builder.String(), i
}

func isMusicID(value string) bool {
	if len(value) != 14 || !strings.HasPrefix(value, "00") {
		return false
	}
	for _, c := range value {
		if !isASCIIAlnum(byte(c)) {
			return false
		}
	}
	return true
}

func isMusicFileName(value string) bool {
	lower := strings.ToLower(value)
	extension := ""
	for _, ext := range []string{".mgg", ".mflac", ".mmp4"} {
		if strings.HasSuffix(lower, ext) {
			extension = ext
			break
		}
	}
	if extension == "" {
		return false
	}
	base := lower[:len(lower)-len(extension)]
	return len(base) >= 4 && isASCIIAlnum(base[0])
}

func isASCIIAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isBase64Text(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, c := range value {
		if isASCIIAlnum(c) || c == '+' || c == '/' || c == '=' {
			continue
		}
		return false
	}
	return true
}

func readLast(r io.ReadSeeker, length int64) ([]byte, error) {
	if _, err := r.Seek(-length, io.SeekEnd); err != nil {
		return nil, err
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
