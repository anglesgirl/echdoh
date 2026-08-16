// 种子上游拉取（2026-08-16）：从 ech-config.anglesgirl.eu.org 的 TXT 记录
// 动态获取 DoH 上游列表（doh=/doh2=/doh3=，7 个 CF gateway 端点轮换）。
// 用 IP 直连 DoH 查 TXT（AGENTS.md 铁律：域名解析环节可被劫持，IP 直连跳过）。
package echdoh

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const seedDomain = "ech-config.anglesgirl.eu.org."

// seedIPDoHs：国内 IP 直连 DoH（JSON /resolve 端点），360 / DNSPod / 腾讯备用
var seedIPDoHs = []string{
	"https://101.226.4.6/resolve",
	"https://120.53.53.53/resolve",
	"https://1.12.12.12/resolve",
}

type seedResolveResp struct {
	Status int `json:"status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// fetchSeedTXT 用 IP DoH 种子查 TXT，返回 k=v 字段表。
func fetchSeedTXT() map[string]string {
	client := &http.Client{Timeout: 5 * time.Second}
	for _, ep := range seedIPDoHs {
		u := fmt.Sprintf("%s?name=%s&type=TXT", ep, url.QueryEscape(strings.TrimSuffix(seedDomain, ".")))
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var r seedResolveResp
		if err := json.Unmarshal(body, &r); err != nil || r.Status != 0 {
			continue
		}
		fields := map[string]string{}
		for _, a := range r.Answer {
			if a.Type != 16 { // TXT
				continue
			}
			for _, chunk := range splitTXTChunks(a.Data) {
				if i := strings.Index(chunk, "="); i > 0 {
					k := strings.ToLower(strings.TrimSpace(chunk[:i]))
					v := strings.TrimSpace(chunk[i+1:])
					if k != "" && v != "" {
						fields[k] = v
					}
				}
			}
		}
		if len(fields) > 0 {
			return fields
		}
	}
	return nil
}

// splitTXTChunks 拆 TXT 多 chunk（引号包裹 + 分号结尾）。
func splitTXTChunks(data string) []string {
	s := strings.Trim(data, `"`)
	var out []string
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// fetchSeedUpstreams 从种子 TXT 提取 doh=/doh2=/doh3= 的完整上游列表。
// 返回 nil 表示种子不可用（调用方用传入的 upstreams 兜底）。
func fetchSeedUpstreams() []string {
	fields := fetchSeedTXT()
	if fields == nil {
		slog("seed TXT unavailable, keep passed upstreams")
		return nil
	}
	var ups []string
	for _, k := range []string{"doh", "doh2", "doh3"} {
		if v, ok := fields[k]; ok {
			for _, u := range strings.Split(v, ",") {
				u = strings.TrimSpace(u)
				if strings.HasPrefix(u, "https://") && u != "" {
					ups = append(ups, u)
				}
			}
		}
	}
	if len(ups) == 0 {
		slog("seed TXT has no doh endpoints")
		return nil
	}
	slog("seed upstreams from TXT: %d endpoints (%s...)", len(ups), ups[0])
	return ups
}
