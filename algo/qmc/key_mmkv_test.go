package qmc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
	"unlock-music.dev/mmkv"
)

// fakeVault is an in-memory mmkv.Vault used to exercise the lookup order
// without touching the real QQ Music vaults.
type fakeVault map[string][]byte

func (f fakeVault) Keys() []string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	return keys
}

func (f fakeVault) GetRaw(key string) ([]byte, bool) {
	v, ok := f[key]
	return v, ok
}

func (f fakeVault) GetBytes(key string) ([]byte, error) {
	v, ok := f[key]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return v, nil
}

func (f fakeVault) GetString(key string) (string, error) {
	v, err := f.GetBytes(key)
	return string(v), err
}

func resetMMKVState() {
	streamKeyVault = nil
	streamKeyVaults = nil
	mmkvInitOnce = sync.Once{}
	mmkvInitErr = nil
}

// The plaintext vault of QQ Music 20.x+ is an empty placeholder; the keys live
// in the encrypted vaults, so a miss in the first vault must keep looking
// instead of giving up.
func TestLookupKeyFallsBackToEncryptedVaults(t *testing.T) {
	resetMMKVState()
	t.Cleanup(resetMMKVState)

	streamKeyVault = fakeVault{"/music/other.mflac": []byte("primary")}
	streamKeyVaults = []mmkv.Vault{
		fakeVault{"/music/other.mflac": []byte("duplicate")},
		fakeVault{"/music/齐秦-大约在冬季.mflac": []byte("encrypted-ekey")},
	}

	got, err := lookupKeyInVaults("/music/齐秦-大约在冬季.mflac")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if string(got) != "encrypted-ekey" {
		t.Fatalf("unexpected key %q", got)
	}
}

// macOS rewrites filenames between NFC and NFD; the basename fallback must
// normalize both sides.
func TestLookupKeyMatchesNormalizedBasename(t *testing.T) {
	resetMMKVState()
	t.Cleanup(resetMMKVState)

	const (
		nfc = "ぜ.mflac" // e3 81 9c
		nfd = "せ\u3099.mflac"
	)
	if nfc == nfd {
		t.Fatal("test literals must differ before normalization")
	}

	streamKeyVault = fakeVault{}
	streamKeyVaults = []mmkv.Vault{fakeVault{"/music/" + nfd: []byte("nfd-ekey")}}

	got, err := lookupKeyInVaults("/music/" + nfc)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if string(got) != "nfd-ekey" {
		t.Fatalf("unexpected key %q", got)
	}
}

func TestLookupKeyNotFound(t *testing.T) {
	resetMMKVState()
	t.Cleanup(resetMMKVState)

	streamKeyVault = fakeVault{"/music/a.mflac": []byte("a")}
	if _, err := lookupKeyInVaults("/music/b.mflac"); err == nil {
		t.Fatal("expected an error for a missing key")
	}
}

// writeZeroVault reproduces the placeholder QQ Music 20.x+ leaves behind:
// both the vault and its .crc file are 16 KiB of zeros.
func writeZeroVault(t *testing.T, dir, id string) {
	t.Helper()
	zeros := make([]byte, 16384)
	for _, name := range []string{id, id + ".crc"} {
		if err := os.WriteFile(filepath.Join(dir, name), zeros, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// An empty plaintext vault with no crypto key must produce one actionable
// error instead of the old generic "open mmkv vault" chain.
func TestOpenMMKVVaultsEmptyPlainVaultNeedsCryptoKey(t *testing.T) {
	resetMMKVState()
	t.Cleanup(resetMMKVState)

	prevKey := VaultCryptoKey
	VaultCryptoKey = ""
	t.Cleanup(func() { VaultCryptoKey = prevKey })

	dir := t.TempDir()
	writeZeroVault(t, dir, "MMKVStreamEncryptId")

	err := openMMKVVaults(dir, dir, zap.NewNop())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "--qmc-mmkv-key") {
		t.Fatalf("error should point at --qmc-mmkv-key, got: %v", err)
	}
}

// With a crypto key configured but no encrypted vault present, the failure
// must name the encrypted vaults rather than the plaintext one.
func TestOpenMMKVVaultsEmptyPlainVaultWithCryptoKey(t *testing.T) {
	resetMMKVState()
	t.Cleanup(resetMMKVState)

	prevKey := VaultCryptoKey
	VaultCryptoKey = "0123456789abcdef"
	t.Cleanup(func() { VaultCryptoKey = prevKey })

	dir := t.TempDir()
	writeZeroVault(t, dir, "MMKVStreamEncryptId")

	err := openMMKVVaults(dir, dir, zap.NewNop())
	if err == nil {
		t.Fatal("expected an error when no encrypted vault can be opened")
	}
	if errors.Is(err, mmkv.ErrVaultEmpty) {
		t.Fatalf("the plaintext vault being empty is expected; got: %v", err)
	}
}
