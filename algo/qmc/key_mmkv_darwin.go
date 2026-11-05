//go:build darwin

package qmc

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"

	"howett.net/plist"
)

// mmkvKeySlots is how many vault slots QQ Music derives keys for. Slot idx maps
// to one MMKV instance (its mmapID is derived from the same index), and the
// client only keeps a handful of them.
const mmkvKeySlots = 32

// deriveMMKVVaultKeys reproduces the key material QQ Music 20.x+ feeds into
// MMKV, so the encrypted vaults can be opened without a debugger:
//
//	cryptKey = hex(md5(OpenUDID + sprintf("%02x", idx+42310)))[:16]
//
// MMKV truncates the key to AES_KEY_LEN (16 bytes), therefore the effective key
// is the ASCII hex prefix, not the decoded digest. The matching mmapID is the
// OpenUDID with its alphanumerics rotated by (idx+3); since vaults are found by
// scanning the iData directory, the ID derivation is not needed here.
func deriveMMKVVaultKeys() []string {
	return deriveKeysFromUDID(readOpenUDID())
}

// deriveKeysFromUDID is the pure part of the derivation, kept separate so it can
// be tested against known vectors.
func deriveKeysFromUDID(udid string) []string {
	if udid == "" {
		return nil
	}

	keys := make([]string, 0, mmkvKeySlots)
	for idx := range mmkvKeySlots {
		sum := md5.Sum([]byte(udid + fmt.Sprintf("%02x", idx+42310)))
		keys = append(keys, hex.EncodeToString(sum[:])[:16])
	}
	return keys
}

// readOpenUDID reads the OpenUDID the client stores in its preferences. It is
// the only per-install secret the vault key derivation depends on.
func readOpenUDID() string {
	for _, path := range loginPlistCandidates() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var top map[string]any
		if _, err := plist.Unmarshal(data, &top); err != nil {
			continue
		}
		if udid := openUDIDFrom(top); udid != "" {
			return udid
		}
	}
	return ""
}

func openUDIDFrom(top map[string]any) string {
	switch v := top["OpenUDID"].(type) {
	case string:
		return v
	case map[string]any:
		if s, ok := v["OpenUDID"].(string); ok {
			return s
		}
	case []byte:
		// The value is sometimes stored as a nested serialized plist.
		var inner map[string]any
		if _, err := plist.Unmarshal(v, &inner); err == nil {
			if s, ok := inner["OpenUDID"].(string); ok {
				return s
			}
		}
	}
	return ""
}
