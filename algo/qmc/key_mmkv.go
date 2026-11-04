package qmc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/samber/lo"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	"golang.org/x/text/unicode/norm"
	"unlock-music.dev/mmkv"
)

var streamKeyVault mmkv.Vault
var streamKeyVaults []mmkv.Vault // fallback vaults for QQ Music 20.x+ encrypted vaults

// VaultCryptoKey is the AES-128 key used to decrypt version-3 encrypted MMKV vaults.
// Set via CLI flag --qmc-mmkv-key or by calling SetVaultCryptoKey.
var VaultCryptoKey string

// SetVaultCryptoKey sets the crypto key for encrypted MMKV vaults.
func SetVaultCryptoKey(key string) {
	VaultCryptoKey = key
}

// TODO: move to factory
func readKeyFromMMKV(file string, logger *zap.Logger) ([]byte, error) {
	if file == "" {
		return nil, errors.New("file path is required while reading key from mmkv")
	}

	//goland:noinspection GoBoolExpressions
	if runtime.GOOS != "darwin" {
		return nil, errors.New("mmkv vault not supported on this platform")
	}

	if streamKeyVault == nil {
		mmkvDir, err := getRelativeMMKVDir(file)
		if err != nil {
			mmkvDir, err = getDefaultMMKVDir()
			if err != nil {
				return nil, fmt.Errorf("mmkv key valut not found: %w", err)
			}
		}

		mgr, err := mmkv.NewManager(mmkvDir)
		if err != nil {
			return nil, fmt.Errorf("init mmkv manager: %w", err)
		}

		streamKeyVault, err = mgr.OpenVault("MMKVStreamEncryptId")
		if err != nil {
			// Plain vault failed (e.g., empty/corrupted) — try encrypted vaults for QQ Music 20.x+
			logger.Warn("plain mmkv vault open failed, trying encrypted vaults", zap.Error(err))
			encErr := tryInitEncryptedVault(logger)
			if encErr != nil {
				return nil, fmt.Errorf("open mmkv vault: %w (encrypted fallback: %w)", err, encErr)
			}
		} else if len(streamKeyVault.Keys()) == 0 {
			// Vault opened but is empty — try encrypted vaults for QQ Music 20.x+
			logger.Debug("plain mmkv vault is empty, trying encrypted vaults")
			encErr := tryInitEncryptedVault(logger)
			if encErr != nil {
				logger.Debug("encrypted vault fallback also failed", zap.Error(encErr))
			}
		}

		if streamKeyVault != nil {
			logger.Debug("mmkv vault opened", zap.Strings("keys", streamKeyVault.Keys()))
		}
	}

	_, partName := filepath.Split(file)
	partName = normalizeUnicode(partName)

	buf, err := streamKeyVault.GetBytes(file)
	if buf == nil {
		filePaths := streamKeyVault.Keys()
		fileNames := lo.Map(filePaths, func(filePath string, _ int) string {
			_, name := filepath.Split(filePath)
			return normalizeUnicode(name)
		})

		for _, key := range fileNames { // fallback: match filename only
			if key != partName {
				continue
			}
			idx := slices.Index(fileNames, key)
			buf, err = streamKeyVault.GetBytes(filePaths[idx])
			if err != nil {
				logger.Warn("read key from mmkv", zap.String("key", filePaths[idx]), zap.Error(err))
			}
		}

	}

	if len(buf) == 0 {
		return nil, errors.New("key not found in mmkv vault")
	}

	return deriveKey(buf)
}

func OpenMMKV(mmkvPath string, key string, logger *zap.Logger) error {
	filePath, fileName := filepath.Split(mmkvPath)
	mgr, err := mmkv.NewManager(filePath)
	// filePath, fileName := filepath.Split(mmkvPath)
	// mgr, err := mmkv.NewManager(filepath.Dir(filePath))
	if err != nil {
		return fmt.Errorf("init mmkv manager: %w", err)
	}

	// If `vaultKey` is empty, the key is ignored.
	streamKeyVault, err = mgr.OpenVaultCrypto(fileName, key)
	if err != nil {
		return fmt.Errorf("open mmkv vault: %w", err)
	}

	logger.Debug("mmkv vault opened", zap.Strings("keys", streamKeyVault.Keys()))
	return nil
}

// /
func readKeyFromMMKVCustom(mid string) ([]byte, error) {
	if streamKeyVault == nil {
		return nil, fmt.Errorf("mmkv vault not loaded")
	}

	// Try primary vault first
	eKey, err := streamKeyVault.GetBytes(mid)
	if err == nil {
		return deriveKey(eKey)
	}

	// Fallback: try every encrypted vault loaded during auto-discovery.
	//
	// Do NOT compare the vaults with == to skip the primary one: their dynamic
	// type (mmkv.vault) is a map, which is not comparable, so comparing two
	// interface values panics at runtime. Re-querying the primary vault is
	// cheap and harmless.
	for _, v := range streamKeyVaults {
		eKey, fallbackErr := v.GetBytes(mid)
		if fallbackErr == nil {
			return deriveKey(eKey)
		}
	}

	return nil, fmt.Errorf("get eKey error: %w", err)
}

// tryInitEncryptedVault attempts to locate and open an encrypted version-3 MMKV vault
// in the default iData directory. This is needed for QQ Music 20.x+ which stores
// stream encryption keys in AES-encrypted vaults instead of the plain MMKVStreamEncryptId.
func tryInitEncryptedVault(logger *zap.Logger) error {
	if VaultCryptoKey == "" {
		logger.Warn("tryInitEncryptedVault: no crypto key configured")
		return fmt.Errorf("no vault crypto key configured")
	}
	logger.Info("tryInitEncryptedVault: attempting with crypto key", zap.Int("key_len", len(VaultCryptoKey)))

	mmkvDir, err := getDefaultMMKVDir()
	if err != nil {
		// getDefaultMMKVDir checks for MMKVStreamEncryptId existence, which may fail.
		// Reconstruct the dir path directly.
		homeDir, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return fmt.Errorf("cannot locate mmkv dir: %w (original: %w)", homeErr, err)
		}
		mmkvDir = filepath.Join(
			homeDir,
			"Library/Containers/com.tencent.QQMusicMac/Data",
			"Library/Application Support/QQMusicMac/iData",
		)
	}

	mgr, mgrErr := mmkv.NewManager(mmkvDir)
	if mgrErr != nil {
		return fmt.Errorf("init mmkv manager for encrypted vault: %w", mgrErr)
	}

	// Scan for version-3 encrypted vault candidates in iData directory.
	// Known encrypted vault IDs used by QQ Music 20.x+:
	candidateIDs := []string{"797g0", "808h18", "131k4", "919i299", "020j3005"}

	// Also scan the directory for any version-3 vault files we might have missed.
	entries, readErr := os.ReadDir(mmkvDir)
	if readErr == nil {
		for _, entry := range entries {
			name := entry.Name()
			// Skip .crc files and known non-vault files
			if strings.HasSuffix(name, ".crc") {
				continue
			}
			// Skip known non-encrypted vaults and special directories
			if name == "MMKVStreamEncryptId" || name == "mmkv.default" ||
				strings.HasPrefix(name, "P2P") || name == "specialCharacter" {
				continue
			}
			// Add if not already in candidates
			found := false
			for _, c := range candidateIDs {
				if c == name {
					found = true
					break
				}
			}
			if !found {
				candidateIDs = append(candidateIDs, name)
			}
		}
	}

	for _, vaultID := range candidateIDs {
		vault, openErr := mgr.OpenVaultCrypto(vaultID, VaultCryptoKey)
		if openErr != nil {
			logger.Warn("try encrypted vault failed",
				zap.String("vault", vaultID),
				zap.Error(openErr))
			continue
		}

		// Verify the vault has usable keys by checking if it has any entries
		keys := vault.Keys()
		if len(keys) == 0 {
			logger.Debug("encrypted vault opened but is empty",
				zap.String("vault", vaultID))
			continue
		}

		logger.Debug("encrypted mmkv vault loaded",
			zap.String("vault", vaultID),
			zap.Int("keys", len(keys)))

		// Store all viable vaults for fallback lookup
		streamKeyVaults = append(streamKeyVaults, vault)

		// Set the primary vault to the first viable one
		if streamKeyVault == nil {
			streamKeyVault = vault
		}
	}

	if streamKeyVault != nil {
		logger.Info("encrypted mmkv vault(s) loaded",
			zap.Int("vaults", len(streamKeyVaults)),
			zap.Int("total_keys", func() int {
				count := 0
				for _, v := range streamKeyVaults {
					count += len(v.Keys())
				}
				return count
			}()))
		return nil
	}

	return fmt.Errorf("no compatible encrypted vault found")
}

// / getRelativeMMKVDir get mmkv dir relative to file (legacy QQMusic for macOS behaviour)
func getRelativeMMKVDir(file string) (string, error) {
	mmkvDir := filepath.Join(filepath.Dir(file), "../mmkv")
	if _, err := os.Stat(mmkvDir); err != nil {
		return "", fmt.Errorf("stat default mmkv dir: %w", err)
	}

	keyFile := filepath.Join(mmkvDir, "MMKVStreamEncryptId")
	if _, err := os.Stat(keyFile); err != nil {
		return "", fmt.Errorf("stat default mmkv file: %w", err)
	}

	return mmkvDir, nil
}

func getDefaultMMKVDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get user home dir: %w", err)
	}

	mmkvDir := filepath.Join(
		homeDir,
		"Library/Containers/com.tencent.QQMusicMac/Data",
		"Library/Application Support/QQMusicMac/iData",
	)
	if _, err := os.Stat(mmkvDir); err != nil {
		return "", fmt.Errorf("stat default mmkv dir: %w", err)
	}

	keyFile := filepath.Join(mmkvDir, "MMKVStreamEncryptId")
	if _, err := os.Stat(keyFile); err != nil {
		return "", fmt.Errorf("stat default mmkv file: %w", err)
	}

	return mmkvDir, nil
}

// normalizeUnicode normalizes unicode string to NFC.
// since macOS may change some characters in the file name.
// e.g. "ぜ"(e3 81 9c) -> "ぜ"(e3 81 9b e3 82 99)
func normalizeUnicode(str string) string {
	return norm.NFC.String(str)
}
