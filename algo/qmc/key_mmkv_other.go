//go:build !darwin

package qmc

// deriveMMKVVaultKeys is macOS-only: the vault key is derived from the QQ Music
// install's OpenUDID, which only exists in the macOS client's preferences.
func deriveMMKVVaultKeys() []string { return nil }
