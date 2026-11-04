package qmc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"unlock-music.dev/cli/algo/qmc/client"
)

var (
	keySourceMu       sync.RWMutex
	manualEkey        string
	onlineEkeyAllowed = true
)

// SetManualEkey injects a user-supplied base64 ekey. It takes precedence over
// MMKV and online lookup, but not over a key embedded in the file tail.
func SetManualEkey(ekey string) {
	keySourceMu.Lock()
	manualEkey = ekey
	keySourceMu.Unlock()
}

// SetOnlineEkey enables or disables the GetEVkey API fallback for musicex files.
func SetOnlineEkey(enabled bool) {
	keySourceMu.Lock()
	onlineEkeyAllowed = enabled
	keySourceMu.Unlock()
}

func getManualEkey() string {
	keySourceMu.RLock()
	defer keySourceMu.RUnlock()
	return manualEkey
}

func isOnlineEkeyAllowed() bool {
	keySourceMu.RLock()
	defer keySourceMu.RUnlock()
	return onlineEkeyAllowed
}

// fetchEkeyHook is replaced by tests to avoid network access.
var fetchEkeyHook func(mid, filename string) ([]byte, error)

func fetchEkey(mid, filename string, logger *zap.Logger) ([]byte, error) {
	if fetchEkeyHook != nil {
		return fetchEkeyHook(mid, filename)
	}
	return fetchOnlineEkey(mid, filename, logger)
}

func fetchOnlineEkey(mid, filename string, logger *zap.Logger) ([]byte, error) {
	credentials, err := loadCredentials()
	if err != nil {
		return nil, fmt.Errorf("读取 QQ 音乐登录信息: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ekey, err := client.NewQQMusicClient().GetEVkey(
		ctx, mid, filename, credentials.Uin, credentials.Authst, credentials.LoginType,
	)
	if err != nil {
		return nil, err
	}
	logger.Debug("fetched ekey from QQ Music API",
		zap.String("songmid", mid), zap.String("filename", filename))
	return deriveKey([]byte(ekey))
}
