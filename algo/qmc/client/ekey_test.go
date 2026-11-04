package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetEVkey(t *testing.T) {
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		_, _ = w.Write([]byte(`{"code":0,"req_1":{"code":0,"data":{"midurlinfo":[{"ekey":"dGVzdC1la2V5"}]}}}`))
	}))
	defer server.Close()

	c := NewQQMusicClient()
	c.endpoint = server.URL
	ekey, err := c.GetEVkey(context.Background(), "002N4Yw52prWDN", "F0M0002N4Yw52prWDN.mflac", "12345", "auth-token", "3")
	if err != nil {
		t.Fatal(err)
	}
	if ekey != "dGVzdC1la2V5" {
		t.Fatalf("ekey = %q", ekey)
	}
	comm, _ := body["comm"].(map[string]any)
	if comm["authst"] != "auth-token" || comm["uin"] != "12345" {
		t.Fatalf("missing credentials in comm: %#v", comm)
	}
	req1, _ := body["req_1"].(map[string]any)
	param, _ := req1["param"].(map[string]any)
	if strings.Join(toStrings(param["filename"]), ",") != "F0M0002N4Yw52prWDN.mflac" {
		t.Fatalf("filename not forwarded: %#v", param)
	}
	if strings.Join(toStrings(param["songmid"]), ",") != "002N4Yw52prWDN" {
		t.Fatalf("songmid not forwarded: %#v", param)
	}
}

func toStrings(value any) []string {
	values, _ := value.([]any)
	out := make([]string, 0, len(values))
	for _, item := range values {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
