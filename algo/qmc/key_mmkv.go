package qmc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/text/unicode/norm"
	"unlock-music.dev/mmkv"
)

var streamKeyVault mmkv.Vault
var streamKeyVaults []mmkv.Vault // fallback vaults for QQ Music 20.x+ encrypted vaults

// Vault discovery runs at most once per process: on QQ Music 20.x+ the
// plaintext vault is a zeroed placeholder, so retrying it for every input file
// only repeated the same warnings.
var (
	mmkvInitOnce sync.Once
	mmkvInitErr  error
)

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

	if err := initMMKVVaults(file, logger); err != nil {
		return nil, err
	}

	buf, err := lookupKeyInVaults(file)
	if err != nil {
		return nil, err
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

// lookupKeyInVaults returns the raw ekey stored for file, consulting the primary
// vault first and then every encrypted vault loaded during discovery. Older
// builds key entries by absolute path, newer ones by media file name, and macOS
// may hand the name out in a different Unicode normalization, so three passes
// are needed.
func lookupKeyInVaults(file string) ([]byte, error) {
	vaults := make([]mmkv.Vault, 0, 1+len(streamKeyVaults))
	if streamKeyVault != nil {
		vaults = append(vaults, streamKeyVault)
	}
	vaults = append(vaults, streamKeyVaults...)
	if len(vaults) == 0 {
		return nil, errors.New("no mmkv vault loaded")
	}

	for _, v := range vaults {
		if buf, err := v.GetBytes(file); err == nil && len(buf) > 0 {
			return buf, nil
		}
	}

	_, partName := filepath.Split(file)
	partName = normalizeUnicode(partName)
	for _, v := range vaults {
		for _, key := range v.Keys() {
			_, name := filepath.Split(key)
			if normalizeUnicode(name) != partName {
				continue
			}
			if buf, err := v.GetBytes(key); err == nil && len(buf) > 0 {
				return buf, nil
			}
		}
	}

	return nil, fmt.Errorf("key not found in mmkv vault: %s", partName)
}

// readKeyFromMMKVCustom looks the ekey up by the media file name / mid stored
// in the musicex footer.
func readKeyFromMMKVCustom(mid string, logger *zap.Logger) ([]byte, error) {
	if err := initMMKVVaults("", logger); err != nil {
		return nil, fmt.Errorf("mmkv vault not loaded: %w", err)
	}

	buf, err := lookupKeyInVaults(mid)
	if err != nil {
		return nil, fmt.Errorf("get eKey error: %w", err)
	}

	return deriveKey(buf)
}

// initMMKVVaults locates and opens the MMKV key vaults once per process, so a
// legacy placeholder vault does not repeat the same warnings for every file.
func initMMKVVaults(file string, logger *zap.Logger) error {
	mmkvInitOnce.Do(func() {
		// An explicit --qmc-mmkv vault takes precedence over auto-discovery.
		if streamKeyVault != nil {
			return
		}
		mmkvDir, err := getRelativeMMKVDir(file)
		if err != nil {
			mmkvDir, err = getDefaultMMKVDir()
			if err != nil {
				mmkvInitErr = fmt.Errorf("mmkv key vault not found: %w", err)
				return
			}
		}
		mmkvInitErr = openMMKVVaults(mmkvDir, encryptedVaultDir(), logger)
	})
	return mmkvInitErr
}

// encryptedVaultDir returns the iData directory holding the encrypted vaults.
// getDefaultMMKVDir insists on MMKVStreamEncryptId existing, which 20.x+ may not
// keep, so fall back to the well-known path.
func encryptedVaultDir() string {
	if dir, err := getDefaultMMKVDir(); err == nil {
		return dir
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(
		homeDir,
		"Library/Containers/com.tencent.QQMusicMac/Data",
		"Library/Application Support/QQMusicMac/iData",
	)
}

// openMMKVVaults opens the plaintext vault in plainDir and, when a crypto key is
// configured, the AES-encrypted vaults in encDir. An empty plaintext vault is
// expected on QQ Music 20.x+ and is only reported at debug level.
func openMMKVVaults(plainDir, encDir string, logger *zap.Logger) error {
	streamKeyVault = nil
	streamKeyVaults = nil

	mgr, err := mmkv.NewManager(plainDir)
	if err != nil {
		return fmt.Errorf("init mmkv manager: %w", err)
	}

	var plainErr error
	vault, err := mgr.OpenVault("MMKVStreamEncryptId")
	switch {
	case errors.Is(err, mmkv.ErrVaultEmpty):
		// QQ Music 20.x+ keeps the legacy plaintext vault as zeroed pages and
		// moved the keys into the encrypted vaults; this is not a failure.
		logger.Debug("plain mmkv vault is empty (QQ Music 20.x+ keeps it as a placeholder)")
		plainErr = err
	case err != nil:
		logger.Warn("plain mmkv vault open failed", zap.Error(err))
		plainErr = err
	case len(vault.Keys()) == 0:
		logger.Debug("plain mmkv vault holds no keys")
		plainErr = errors.New("plain mmkv vault is empty")
	default:
		streamKeyVault = vault
		logger.Debug("mmkv vault opened", zap.Strings("keys", vault.Keys()))
	}

	if VaultCryptoKey == "" {
		if plainErr != nil {
			return fmt.Errorf("no usable MMKV vault: %v; the encrypted vaults need --qmc-mmkv-key", plainErr)
		}
		return nil
	}

	encErr := openEncryptedVaults(encDir, logger)
	if encErr != nil {
		if plainErr != nil {
			return fmt.Errorf("plaintext vault unusable (%v); encrypted vaults: %w", plainErr, encErr)
		}
		logger.Debug("encrypted mmkv vaults unusable, keeping the plaintext vault", zap.Error(encErr))
	}
	return nil
}

// openEncryptedVaults opens the AES-encrypted vaults that QQ Music 20.x+ writes
// and records every vault holding keys as a lookup fallback.
func openEncryptedVaults(mmkvDir string, logger *zap.Logger) error {
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
			// Candidates are speculative: non-matching IDs are expected to fail.
			logger.Debug("encrypted vault not usable",
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

	if len(streamKeyVaults) == 0 {
		return fmt.Errorf("no compatible encrypted vault found in %s", mmkvDir)
	}

	totalKeys := 0
	for _, v := range streamKeyVaults {
		totalKeys += len(v.Keys())
	}
	logger.Debug("encrypted mmkv vault(s) loaded",
		zap.Int("vaults", len(streamKeyVaults)),
		zap.Int("total_keys", totalKeys))
	return nil
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
