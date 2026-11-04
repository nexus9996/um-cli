//go:build !darwin && !windows

package qmc

import "errors"

func loadCredentials() (Credentials, error) {
	return Credentials{}, errors.New("当前平台不支持自动读取 QQ 音乐登录信息，请使用 --qmc-ekey 手动提供 ekey")
}
