# Unlock Music Project - CLI Edition

Original: Web Edition https://git.unlock-music.dev/um/web

- [![Build Status](https://git.unlock-music.dev/um/cli/actions/workflows/build.yml/badge.svg)](https://git.unlock-music.dev/um/cli/actions?workflow=build.yml)
- [Release Download](https://git.unlock-music.dev/um/cli/releases/latest)
- [Latest Build](https://git.unlock-music.dev/um/cli/actions)

> **WARNING**
> 在本站 fork 不会起到备份的作用，只会浪费服务器储存空间。如无必要请勿 fork 该仓库。

## Features

- [x] All Algorithm Supported By `unlock-music/web`
- [x] Complete Metadata & Cover Image

## Release

[Latest release](https://git.unlock-music.dev/um/cli/releases/latest).

## Install from source

- Requirements: **Golang 1.23.3**

1. run `go install unlock-music.dev/cli/cmd/um@master`

### Build from repo source

1. Pull repo source.
2. Build with `go build ./cmd/um`.

It will produce `um` or `um.exe` (Windows).

## How to use

- Drag the encrypted file to `um.exe` (Tested on Windows)
- Run: `./um [-o <output dir>] [-i] <input dir/file>`
- Use `./um -h` to show help menu

## QMC key sources (musicex / QTag / legacy / QMCv1)

`um` recognises all QMC containers by the file tail, not only the extension:

| Tail | Key source |
| --- | --- |
| `QTag` | Base64 ekey embedded in the tail |
| little-endian length + ekey | Legacy PC tail, embedded key |
| no tail / unknown | QMCv1 static cipher box (keyless) |
| `STag` | None; rejected with an actionable error |

On macOS the encrypted MMKV vaults (`iData/797g0`, `808h18`, …) that QQ Music
20.x+ uses for per-file ekeys are opened automatically: the vault key is derived
from the install's `OpenUDID` as `md5(OpenUDID + sprintf("%02x", slot+42310))`,
of which MMKV uses the first 16 bytes. `--qmc-mmkv-key` overrides this and
`--qmc-ekey` bypasses it entirely.

`musicex` (`.mgg` / `.mflac` / `.mmp4`) has no key inside the file. The decoder
locates the UTF-16 media ID / resource filename in the footer (works for both
the 192-byte and 208-byte layouts), strips exactly the footer, then tries:

1. `--qmc-ekey <base64>` or `--qmc-ekey-file <path>` (manual key)
2. macOS MMKV vaults (`--qmc-mmkv`, `--qmc-mmkv-key`, or auto-discovered
   encrypted vaults under QQ Music `iData`)
3. QQ Music `music.vkey.GetEVkey` using the local login
   (macOS plist / Windows process memory). Disable this network fallback with
   `--qmc-no-online-key`.

Examples:

```bash
./um -i song.mflac -o out --qmc-ekey "BASE64_EKEY"
./um -i song.mflac -o out --qmc-ekey-file ekey.txt --qmc-no-online-key
./um -i /path/to/iQmc -o out --qmc-mmkv-key "16-char-key"
```

QMCv1/QTag/legacy files never require login or network access.
