//go:build darwin

package qmc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"howett.net/plist"
)

func loginPlistCandidates() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, "Library/Containers/com.tencent.QQMusicMac/Data/Library/Preferences/com.tencent.QQMusicMac.plist"),
		filepath.Join(home, "Library/Preferences/com.tencent.QQMusicMac.plist"),
	}
}

// loadCredentials reads the most recently modified readable login plist.
// QQ Music 11.x stores the archive outside the sandbox container, while older
// versions use the container path, so both must be considered.
func loadCredentials() (Credentials, error) {
	candidates := loginPlistCandidates()
	type candidate struct {
		path    string
		modTime int64
	}
	var readable []candidate
	var permissionErr error
	for _, path := range candidates {
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrPermission) && permissionErr == nil {
				permissionErr = fmt.Errorf(
					"读取 %s 被拒绝；请在「系统设置 → 隐私与安全性 → 完全磁盘访问权限」中允许终端或 um: %w",
					path, err)
			}
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			if errors.Is(err, os.ErrPermission) && permissionErr == nil {
				permissionErr = fmt.Errorf("读取 %s 被拒绝: %w", path, err)
			}
			continue
		}
		_ = f.Close()
		readable = append(readable, candidate{path: path, modTime: info.ModTime().UnixNano()})
	}
	if len(readable) == 0 {
		if permissionErr != nil {
			return Credentials{}, permissionErr
		}
		return Credentials{}, errors.New("未找到 QQ 音乐登录信息，请先登录桌面版 QQ 音乐，或使用 --qmc-ekey 手动提供 ekey")
	}
	sort.Slice(readable, func(i, j int) bool { return readable[i].modTime > readable[j].modTime })
	data, err := os.ReadFile(readable[0].path)
	if err != nil {
		return Credentials{}, fmt.Errorf("读取 QQ 音乐登录信息: %w", err)
	}
	return parseCredentials(data)
}

func parseCredentials(data []byte) (Credentials, error) {
	var top map[string]any
	if _, err := plist.Unmarshal(data, &top); err != nil {
		return Credentials{}, fmt.Errorf("解析 QQ 音乐 plist: %w", err)
	}
	raw, ok := top["AutoLoginUserInfo"]
	if !ok {
		return Credentials{}, errors.New("QQ 音乐 plist 中没有 AutoLoginUserInfo（未登录）")
	}
	inner, ok := raw.([]byte)
	if !ok {
		if text, isText := raw.(string); isText {
			inner = []byte(text)
		} else {
			return Credentials{}, errors.New("AutoLoginUserInfo 不是二进制归档")
		}
	}
	var archive map[string]any
	if _, err := plist.Unmarshal(inner, &archive); err != nil {
		return Credentials{}, fmt.Errorf("解析 AutoLoginUserInfo: %w", err)
	}
	objects, _ := archive["$objects"].([]any)
	for _, object := range objects {
		dict, ok := object.(map[string]any)
		if !ok {
			continue
		}
		authstValue, ok := dict["strAuthst"]
		if !ok {
			continue
		}
		authst := resolveString(authstValue, objects)
		uin := resolveString(dict["nUserId"], objects)
		if uin == "" {
			uin = resolveString(dict["strUserAccount"], objects)
		}
		loginType := resolveString(dict["loginType"], objects)
		if loginType == "" {
			loginType = "3"
		}
		if authst != "" && uin != "" {
			return Credentials{Uin: uin, Authst: authst, LoginType: loginType}, nil
		}
	}
	return Credentials{}, errors.New("QQ 音乐登录信息中没有有效的 uin/authst")
}

func resolveString(value any, objects []any) string {
	switch v := value.(type) {
	case plist.UID:
		index := int(v)
		if index >= 0 && index < len(objects) {
			return resolveString(objects[index], objects)
		}
	case string:
		return v
	case uint64:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case int:
		return fmt.Sprintf("%d", v)
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
	}
	return ""
}
