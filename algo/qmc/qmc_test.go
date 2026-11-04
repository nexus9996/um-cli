package qmc

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	"unlock-music.dev/cli/algo/common"
)

func loadTestDataQmcDecoder(filename string) ([]byte, []byte, error) {
	encBody, err := os.ReadFile(fmt.Sprintf("./testdata/%s_raw.bin", filename))
	if err != nil {
		return nil, nil, err
	}
	encSuffix, err := os.ReadFile(fmt.Sprintf("./testdata/%s_suffix.bin", filename))
	if err != nil {
		return nil, nil, err
	}

	target, err := os.ReadFile(fmt.Sprintf("./testdata/%s_target.bin", filename))
	if err != nil {
		return nil, nil, err
	}
	return bytes.Join([][]byte{encBody, encSuffix}, nil), target, nil

}
func TestMflac0Decoder_Read(t *testing.T) {
	tests := []struct {
		name    string
		fileExt string
		wantErr bool
	}{
		{"mflac0_rc4", ".mflac0", false},
		{"mflac_rc4", ".mflac", false},
		{"mflac_map", ".mflac", false},
		{"mgg_map", ".mgg", false},
		{"qmc0_static", ".qmc0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, target, err := loadTestDataQmcDecoder(tt.name)
			if err != nil {
				t.Fatal(err)
			}

			d := NewDecoder(&common.DecoderParams{
				Reader:    bytes.NewReader(raw),
				Extension: tt.fileExt,
			})
			if err := d.Validate(); err != nil {
				t.Errorf("validate file error = %v", err)
			}

			buf := make([]byte, len(target))
			if _, err := io.ReadFull(d, buf); err != nil {
				t.Errorf("read bytes from decoder error = %v", err)
				return
			}
			if !reflect.DeepEqual(buf, target) {
				t.Errorf("Decrypt() got = %v, want %v", buf[:32], target[:32])
			}
		})
	}

}

func TestMflac0Decoder_Validate(t *testing.T) {
	tests := []struct {
		name    string
		fileExt string
		wantErr bool
	}{
		{"mflac0_rc4", ".flac", false},
		{"mflac_map", ".flac", false},
		{"mgg_map", ".ogg", false},
		{"qmc0_static", ".mp3", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, _, err := loadTestDataQmcDecoder(tt.name)
			if err != nil {
				t.Fatal(err)
			}
			d := NewDecoder(&common.DecoderParams{
				Reader:    bytes.NewReader(raw),
				Extension: tt.fileExt,
			})

			if err := d.Validate(); err != nil {
				t.Errorf("read bytes from decoder error = %v", err)
				return
			}
		})
	}
}

func syntheticMapEncrypted(t *testing.T, key, plain []byte) []byte {
	t.Helper()
	c, err := newMapCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	enc := append([]byte(nil), plain...)
	c.Decrypt(enc, 0)
	return enc
}

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// 离线容器：QTag / 旧版尾部自带 ekey，QMCv1 无密钥，三者都不应访问网络或 MMKV。
func TestDecoderOfflineContainers(t *testing.T) {
	key := []byte("0123456789abcdef")
	ekey := []byte(base64.StdEncoding.EncodeToString(key))
	plain := append([]byte("OggS"), bytes.Repeat([]byte{0x42}, 200)...)
	enc := syntheticMapEncrypted(t, key, plain)

	qtagMeta := append(append([]byte(nil), ekey...), []byte(",42,2")...)
	qtag := append(append(append([]byte(nil), enc...), qtagMeta...), be32(uint32(len(qtagMeta)))...)
	qtag = append(qtag, []byte("QTag")...)

	legacy := append(append(append([]byte(nil), enc...), ekey...), le32(uint32(len(ekey)))...)

	static := append([]byte(nil), plain...)
	newStaticCipher().Decrypt(static, 0)

	tests := []struct {
		name string
		ext  string
		data []byte
	}{
		{"qtag", ".mgg", qtag},
		{"legacy", ".mflac", legacy},
		{"static", ".qmc0", static},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDecoder(&common.DecoderParams{
				Reader:    bytes.NewReader(tt.data),
				Extension: tt.ext,
			})
			if err := d.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			got, err := io.ReadAll(d)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("decrypted mismatch: got %x want %x", got[:16], plain[:16])
			}
		})
	}
}

func buildMusicExFooter(mid, filename string) []byte {
	body := make([]byte, 176)
	binary.LittleEndian.PutUint32(body[0:4], 123)
	put := func(off int, s string) {
		for i := 0; i < len(s); i++ {
			body[off+i*2] = s[i]
		}
	}
	put(0x0c, mid)
	put(0x48, filename)
	trailer := make([]byte, 16)
	binary.LittleEndian.PutUint32(trailer[0:4], 0xC0)
	binary.LittleEndian.PutUint32(trailer[4:8], 1)
	copy(trailer[8:], []byte("musicex\x00"))
	return append(body, trailer...)
}

// musicex 不内嵌 ekey：手动 ekey 必须能解开，且 footer 不能被写进输出音频。
func TestMusicExManualEkeyStripsFooter(t *testing.T) {
	key := []byte("0123456789abcdef")
	ekey := base64.StdEncoding.EncodeToString(key)
	plain := append([]byte("fLaC"), bytes.Repeat([]byte{0x24}, 300)...)
	enc := syntheticMapEncrypted(t, key, plain)
	data := append(append([]byte(nil), enc...), buildMusicExFooter("002N4Yw52prWDN", "F0M0002N4Yw52prWDN.mflac")...)

	SetManualEkey(ekey)
	t.Cleanup(func() { SetManualEkey("") })

	d := NewDecoder(&common.DecoderParams{
		Reader:    bytes.NewReader(data),
		Extension: ".mflac",
	})
	if err := d.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("footer leaked into audio or wrong key: got len=%d want len=%d", len(got), len(plain))
	}
}

func TestSTagIsRejected(t *testing.T) {
	meta := []byte("12345,2,002N4Yw52prWDN")
	data := append(append([]byte("audio"), meta...), be32(uint32(len(meta)))...)
	data = append(data, []byte("STag")...)
	d := NewDecoder(&common.DecoderParams{Reader: bytes.NewReader(data), Extension: ".mgg"})
	if err := d.Validate(); err == nil {
		t.Fatal("STag must fail with a missing-key error")
	}
}

// musicex 没有内嵌密钥时，应把尾部解析出的 MID/文件名交给在线取 key 链路。
func TestMusicExOnlineEkeyWiring(t *testing.T) {
	key := []byte("0123456789abcdef")
	SetManualEkey("")
	SetOnlineEkey(true)
	var gotMid, gotFile string
	fetchEkeyHook = func(mid, filename string) ([]byte, error) {
		gotMid, gotFile = mid, filename
		return key, nil
	}
	t.Cleanup(func() {
		fetchEkeyHook = nil
		SetManualEkey("")
		SetOnlineEkey(true)
	})

	plain := append([]byte("fLaC"), bytes.Repeat([]byte{0x11}, 200)...)
	enc := syntheticMapEncrypted(t, key, plain)
	data := append(append([]byte(nil), enc...), buildMusicExFooter("002N4Yw52prWDN", "F0M0002N4Yw52prWDN.mflac")...)
	d := NewDecoder(&common.DecoderParams{Reader: bytes.NewReader(data), Extension: ".mflac"})
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("online ekey path produced wrong audio")
	}
	if gotMid != "002N4Yw52prWDN" || gotFile != "F0M0002N4Yw52prWDN.mflac" {
		t.Fatalf("unexpected lookup keys: mid=%q file=%q", gotMid, gotFile)
	}
}

// 20.x 变体：0x14 字节前缀 + 192 字节 body + 16 字节 trailer。
func TestMusicExNewLayoutStripsFullFooter(t *testing.T) {
	key := []byte("0123456789abcdef")
	ekey := base64.StdEncoding.EncodeToString(key)
	plain := append([]byte("fLaC"), bytes.Repeat([]byte{0x33}, 200)...)
	enc := syntheticMapEncrypted(t, key, plain)

	body := make([]byte, 192)
	putUTF16 := func(off int, value string) {
		for i := 0; i < len(value); i++ {
			body[off+i*2] = value[i]
		}
	}
	putUTF16(0x14+0x0c, "002N4Yw52prWDN")
	putUTF16(0x14+0x48, "F0M0002N4Yw52prWDN.mflac")
	trailer := make([]byte, 16)
	binary.LittleEndian.PutUint32(trailer[0:4], 192)
	binary.LittleEndian.PutUint32(trailer[4:8], 1)
	copy(trailer[8:], "musicex\x00")
	data := append(append(append([]byte(nil), enc...), body...), trailer...)

	SetManualEkey(ekey)
	t.Cleanup(func() { SetManualEkey("") })
	d := NewDecoder(&common.DecoderParams{Reader: bytes.NewReader(data), Extension: ".mflac"})
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("20.x footer leaked: got len=%d want len=%d", len(got), len(plain))
	}
}
