//go:build windows

package qmc

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var virtualQueryEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("VirtualQueryEx")

func loadCredentials() (Credentials, error) {
	uin, err := readWindowsUin()
	if err != nil {
		return Credentials{}, err
	}
	authst, err := scanQQMusicProcesses()
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{Uin: uin, Authst: authst, LoginType: "3"}, nil
}

func readWindowsUin() (string, error) {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return "", errors.New("APPDATA 不存在")
	}
	path := filepath.Join(appdata, "Tencent", "QQMusic", "QQMusicServiceConfig.ini")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("读取 QQMusicServiceConfig.ini 失败，请先登录 QQ 音乐: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if value, ok := strings.CutPrefix(line, "Uin="); ok {
			if value = strings.TrimSpace(value); value != "" {
				return value, nil
			}
		}
	}
	return "", errors.New("QQMusicServiceConfig.ini 中没有 Uin")
}

func scanQQMusicProcesses() (string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "", fmt.Errorf("枚举进程失败: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	var found []string
	var failures []string
	if err := windows.Process32First(snapshot, &entry); err == nil {
		for {
			name := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
			if isQQMusicProcess(name) {
				found = append(found, fmt.Sprintf("%s(PID %d)", name, entry.ProcessID))
				if token, err := scanProcessAuthst(entry.ProcessID); err == nil {
					return token, nil
				} else {
					failures = append(failures, err.Error())
				}
			}
			if err := windows.Process32Next(snapshot, &entry); err != nil {
				break
			}
		}
	}
	if len(found) == 0 {
		return "", errors.New("没有发现运行中的 QQ 音乐进程，请启动并登录桌面版 QQ 音乐后重试")
	}
	return "", fmt.Errorf(
		"已发现 QQ 音乐进程（%s），但未读取到 authst。请确认 QQ 音乐已登录；若以管理员身份运行，请同样以管理员身份运行 um。%s",
		strings.Join(found, "、"),
		firstFailure(failures),
	)
}

func firstFailure(failures []string) string {
	if len(failures) == 0 {
		return ""
	}
	return " 详情：" + failures[0]
}

func isQQMusicProcess(name string) bool {
	switch name {
	case "qqmusic.exe", "qqmusicdesktop.exe", "qqmusicservice.exe", "qqmusiccloud.exe", "qqmusichelper.exe":
		return true
	}
	return strings.HasPrefix(name, "qqmusic")
}

func scanProcessAuthst(pid uint32) (string, error) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return "", errors.New("无法读取 QQMusic.exe 内存；请以管理员身份启动 um 后重试")
	}
	defer windows.CloseHandle(process)

	var address uintptr
	var carry []byte
	for address < ^uintptr(0)-0x10000 {
		var info windows.MemoryBasicInformation
		result, _, _ := virtualQueryEx.Call(
			uintptr(process), address,
			uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info),
		)
		if result == 0 {
			break
		}
		next := info.BaseAddress + info.RegionSize
		if info.State == windows.MEM_COMMIT && info.RegionSize > 0 {
			for offset := uintptr(0); offset < info.RegionSize; {
				count := info.RegionSize - offset
				if count > 1024*1024 {
					count = 1024 * 1024
				}
				buffer := make([]byte, count)
				var read uintptr
				err := windows.ReadProcessMemory(process, info.BaseAddress+offset, &buffer[0], count, &read)
				if err == nil && read > 0 {
					joined := make([]byte, 0, len(carry)+int(read))
					joined = append(joined, carry...)
					joined = append(joined, buffer[:read]...)
					if token := extractAuthst(joined); token != "" {
						return token, nil
					}
					if len(joined) > 2048 {
						joined = joined[len(joined)-2048:]
					}
					carry = joined
				}
				offset += count
			}
		}
		if next <= address {
			break
		}
		address = next
	}
	return "", errors.New("未在 QQ 音乐内存中找到可用 authst")
}

func extractAuthst(data []byte) string {
	for _, key := range [][]byte{[]byte(`"authst"`), []byte(`\"authst\"`), []byte("authst=")} {
		for start := 0; ; {
			index := bytes.Index(data[start:], key)
			if index < 0 {
				break
			}
			index += start
			if token := tokenAfter(data[index+len(key):]); token != "" {
				return token
			}
			start = index + len(key)
		}
	}

	utf16Key := []byte{'a', 0, 'u', 0, 't', 0, 'h', 0, 's', 0, 't', 0}
	for start := 0; ; {
		index := bytes.Index(data[start:], utf16Key)
		if index < 0 {
			break
		}
		index += start
		pairs := data[index:]
		units := make([]uint16, 0, 1024)
		for i := 0; i+1 < len(pairs) && len(units) < 2048; i += 2 {
			units = append(units, uint16(pairs[i])|uint16(pairs[i+1])<<8)
		}
		text := windows.UTF16ToString(units)
		if len(text) <= len("authst") {
			start = index + len(utf16Key)
			continue
		}
		if token := tokenAfter([]byte(text[len("authst"):])); token != "" {
			return token
		}
		start = index + len(utf16Key)
	}
	return ""
}

func tokenAfter(data []byte) string {
	start := 0
	for start < len(data) {
		switch data[start] {
		case ':', '=', ' ', '\t', '\\', '"':
			start++
			continue
		}
		break
	}
	end := start
	for end < len(data) {
		c := data[end]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '=' {
			end++
			continue
		}
		break
	}
	if end-start > 20 {
		return string(data[start:end])
	}
	return ""
}
