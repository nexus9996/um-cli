package client

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
)

type evkeyResponse struct {
	Req1 struct {
		Code int `json:"code"`
		Data struct {
			Retcode    int    `json:"retcode"`
			Msg        string `json:"msg"`
			Midurlinfo []struct {
				Ekey   string `json:"ekey"`
				Ercode string `json:"errcode"`
			} `json:"midurlinfo"`
		} `json:"data"`
	} `json:"req_1"`
}

// GetEVkey requests the per-file key used by musicex/QMC2 files.
// It mirrors the request qmunlock sends with the local QQ Music login token.
func (c *QQMusic) GetEVkey(
	ctx context.Context,
	mid, filename, uin, authst, loginType string,
) (string, error) {
	if uin == "" || authst == "" {
		return "", fmt.Errorf("qqMusicClient[GetEVkey] empty uin/authst")
	}
	if mid == "" || filename == "" {
		return "", fmt.Errorf("qqMusicClient[GetEVkey] empty songmid/filename")
	}
	platform := "20"
	if runtime.GOOS == "windows" {
		platform = "27"
	}
	if loginType == "" {
		loginType = "3"
	}

	payload := map[string]any{
		"comm": map[string]any{
			"authst":       authst,
			"ct":           "19",
			"cv":           "1859",
			"uin":          uin,
			"tmeLoginType": loginType,
			"format":       "json",
		},
		"req_1": map[string]any{
			"module": "music.vkey.GetEVkey",
			"method": "CgiGetEVkey",
			"param": map[string]any{
				"filename":  []string{filename},
				"guid":      "10000",
				"songmid":   []string{mid},
				"songtype":  []int{1},
				"uin":       uin,
				"loginflag": 1,
				"platform":  platform,
				"ctx":       1,
			},
		},
	}

	body, err := c.rpcDoRequest(ctx, payload)
	if err != nil {
		return "", fmt.Errorf("qqMusicClient[GetEVkey] request: %w", err)
	}
	resp := evkeyResponse{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("qqMusicClient[GetEVkey] unmarshal: %w", err)
	}
	if len(resp.Req1.Data.Midurlinfo) > 0 {
		if ekey := resp.Req1.Data.Midurlinfo[0].Ekey; ekey != "" {
			return ekey, nil
		}
	}
	return "", fmt.Errorf(
		"qqMusicClient[GetEVkey] no ekey (code=%d/%d msg=%q errcode=%s)",
		resp.Req1.Code, resp.Req1.Data.Retcode, resp.Req1.Data.Msg,
		firstErrcode(resp),
	)
}

func firstErrcode(resp evkeyResponse) string {
	if len(resp.Req1.Data.Midurlinfo) == 0 {
		return ""
	}
	return resp.Req1.Data.Midurlinfo[0].Ercode
}
