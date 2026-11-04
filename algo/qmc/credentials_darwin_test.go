//go:build darwin

package qmc

import (
	"testing"

	"howett.net/plist"
)

func TestParseLoginArchive(t *testing.T) {
	login := map[string]any{
		"strAuthst": "test-auth",
		"nUserId":   uint64(12345),
		"loginType": "3",
	}
	archive := map[string]any{"$objects": []any{login}}
	inner, err := plist.Marshal(archive, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := plist.Marshal(map[string]any{"AutoLoginUserInfo": inner}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}

	cred, err := parseCredentials(outer)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Uin != "12345" || cred.Authst != "test-auth" || cred.LoginType != "3" {
		t.Fatalf("credentials = %+v", cred)
	}
}

func TestParseLoginArchiveResolvesUID(t *testing.T) {
	login := map[string]any{
		"strAuthst": plist.UID(2),
		"nUserId":   plist.UID(3),
	}
	objs := []any{"$null", login, "uid-auth", "99999"}
	archive := map[string]any{"$objects": objs}
	inner, err := plist.Marshal(archive, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := plist.Marshal(map[string]any{"AutoLoginUserInfo": inner}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := parseCredentials(outer)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Authst != "uid-auth" || cred.Uin != "99999" {
		t.Fatalf("credentials = %+v", cred)
	}
}
