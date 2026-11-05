package mmkv

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_loadVault(t *testing.T) {
	file, err := os.Open("./testdata/mmkv.default")
	require.NoError(t, err)

	v, err := loadVault(file, nil, "")
	require.NoError(t, err)

	assert.Equal(t, 2, len(v.Keys()))

	val, err := v.GetString("world")
	assert.Equal(t, "hello", val)
	assert.NoError(t, err)

	_, err = v.GetBytes("foo")
	assert.Error(t, err)
}

// buildMeta generates the 0x68-byte metadata block that lives in the .crc file.
func buildMeta(version uint32, iv []byte, payload []byte) []byte {
	buf := make([]byte, 0x68)
	binary.LittleEndian.PutUint32(buf[0:4], crc32.ChecksumIEEE(payload))
	binary.LittleEndian.PutUint32(buf[4:8], version)
	if version >= 1 {
		binary.LittleEndian.PutUint32(buf[8:12], 1) // sequence
	}
	copy(buf[12:28], iv)
	if version >= 3 {
		binary.LittleEndian.PutUint32(buf[28:32], uint32(len(payload)))
	}
	return buf
}

// A crypto key supplied for a vault whose metadata predates AES (version < 2)
// has no IV; cipher.NewCFBDecrypter used to panic on that.
func Test_loadVaultCryptoWithoutIVIsErrorNotPanic(t *testing.T) {
	meta, err := loadMetadata(bytes.NewReader(buildMeta(1, nil, nil)))
	require.NoError(t, err)

	// size field 0 -> empty payload
	vaultFile := bytes.NewReader([]byte{0, 0, 0, 0})
	_, err = loadVault(vaultFile, meta, "0123456789abcdef")
	require.Error(t, err)
}

// A wrong crypto key decrypts the payload into garbage; that must surface as an
// error, never as a panic.
func Test_loadVaultCryptoWrongKeyIsErrorNotPanic(t *testing.T) {
	payload := bytes.Repeat([]byte{0xA5}, 64)
	meta, err := loadMetadata(bytes.NewReader(buildMeta(3, bytes.Repeat([]byte{0x11}, 16), payload)))
	require.NoError(t, err)

	buf := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(payload)))
	copy(buf[4:], payload)
	_, err = loadVault(bytes.NewReader(buf), meta, "0123456789abcdef")
	require.Error(t, err)
}

// A corrupt size field must not trigger a multi-gigabyte allocation.
func Test_loadVaultAbsurdSizeIsError(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf[0:4], 0xffffffff)
	_, err := loadVault(bytes.NewReader(buf), nil, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds")
}
