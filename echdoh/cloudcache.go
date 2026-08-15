// 云缓存同步：Turso 数据库共享探测结果（跨设备免重探）。
// 2026-08-16：独立库（不与 LabelScanner 共享），URL/token 由 App 运行时
// 传入（SetCloudCache），不内置凭据（仓库公开）。
//
// 表结构（建库时执行）：
//
//	CREATE TABLE IF NOT EXISTS ech_probe (
//	  k  TEXT PRIMARY KEY,   -- "域名|IP"
//	  ok INTEGER NOT NULL,   -- 1=ECH accepted, 0=否
//	  ts INTEGER NOT NULL    -- unix 秒
//	);
//	CREATE TABLE IF NOT EXISTS ech_scan (
//	  k  TEXT PRIMARY KEY,   -- 可达 CF IP
//	  ts INTEGER NOT NULL
//	);
package echdoh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ccMu         sync.Mutex
	cloudBaseURL string
	cloudToken   string
	cloudPending = map[string]echTestEntry{} // 待推送增量
	cloudStarted bool
)

// SetCloudCache 启用云缓存同步（baseURL 如 https://xxx.turso.io，可带
// libsql:// 前缀自动转）。token 为 Turso 数据库鉴权令牌。传空禁用。
func SetCloudCache(baseURL, token string) {
	ccMu.Lock()
	defer ccMu.Unlock()
	if strings.TrimSpace(baseURL) == "" || strings.TrimSpace(token) == "" {
		cloudBaseURL, cloudToken = "", ""
		return
	}
	cloudBaseURL = strings.TrimSpace(baseURL)
	cloudBaseURL = strings.Replace(cloudBaseURL, "libsql://", "https://", 1)
	cloudToken = strings.TrimSpace(token)
	if !cloudStarted {
		cloudStarted = true
		go cloudSyncLoop()
	}
}

func cloudEnabled() bool {
	ccMu.Lock()
	defer ccMu.Unlock()
	return cloudBaseURL != "" && cloudToken != ""
}

// cloudSyncLoop 每 20s：推送本地增量 + 拉取云端新结果合并。
func cloudSyncLoop() {
	for {
		time.Sleep(20 * time.Second)
		cloudPushPending()
		cloudPull()
	}
}

// cloudPushPending 批量推送待同步的探测结果（INSERT OR REPLACE）。
func cloudPushPending() {
	ccMu.Lock()
	if len(cloudPending) == 0 {
		ccMu.Unlock()
		return
	}
	stmts := make([]map[string]any, 0, len(cloudPending))
	for k, v := range cloudPending {
		stmts = append(stmts, map[string]any{
			"stmt": "INSERT OR REPLACE INTO ech_probe (k, ok, ts) VALUES (:k, :ok, :ts)",
			"args": map[string]any{"k": k, "ok": boolToInt(v.ok), "ts": v.ts.Unix()},
		})
	}
	cloudPending = map[string]echTestEntry{}
	baseURL, token := cloudBaseURL, cloudToken
	ccMu.Unlock()

	if _, err := tursoPipeline(baseURL, token, stmts); err != nil {
		slog("cloud push failed: %v", err)
	}
}

// cloudPull 拉取云端 25h 内的探测结果，合并进本地缓存（云端 ts 新的覆盖）。
func cloudPull() {
	if !cloudEnabled() {
		return
	}
	ccMu.Lock()
	baseURL, token := cloudBaseURL, cloudToken
	ccMu.Unlock()

	resp, err := tursoPipeline(baseURL, token, []map[string]any{
		{
			"stmt": "SELECT k, ok, ts FROM ech_probe WHERE ts > :minTs",
			"args": map[string]any{"minTs": time.Now().Add(-25 * time.Hour).Unix()},
		},
	})
	if err != nil {
		slog("cloud pull failed: %v", err)
		return
	}
	rows := pipelineRows(resp, 0)
	if len(rows) == 0 {
		return
	}
	merged := 0
	echTestMu.Lock()
	for _, r := range rows {
		if len(r) != 3 {
			continue
		}
		k, _ := r[0].(string)
		okF, ok1 := toFloat(r[1])
		tsF, ok2 := toFloat(r[2])
		if k == "" || !ok1 || !ok2 {
			continue
		}
		ts := time.Unix(int64(tsF), 0)
		if e, exists := echTestCache[k]; !exists || ts.After(e.ts) {
			echTestCache[k] = echTestEntry{ok: okF > 0, ts: ts}
			merged++
		}
	}
	echTestMu.Unlock()
	if merged > 0 {
		SaveEchTestCache()
		slog("cloud pull: merged %d entries", merged)
	}
}

// cloudNote 记录一条待推送的探测结果（探测写缓存后调用，限频由调用方控制）。
func cloudNote(k string, v echTestEntry) {
	ccMu.Lock()
	cloudPending[k] = v
	ccMu.Unlock()
}

// cloudPushScan 推送扫描池（ech_scan 表，upsert）。
func cloudPushScan(ips []string) {
	if !cloudEnabled() || len(ips) == 0 {
		return
	}
	ccMu.Lock()
	baseURL, token := cloudBaseURL, cloudToken
	ccMu.Unlock()
	now := time.Now().Unix()
	stmts := make([]map[string]any, 0, len(ips))
	for _, ip := range ips {
		stmts = append(stmts, map[string]any{
			"stmt": "INSERT OR REPLACE INTO ech_scan (k, ts) VALUES (:k, :ts)",
			"args": map[string]any{"k": ip, "ts": now},
		})
	}
	if _, err := tursoPipeline(baseURL, token, stmts); err != nil {
		slog("cloud scan push failed: %v", err)
	}
}

// cloudPullScan 拉取云端扫描池（24h 内可达 IP）。
func cloudPullScan() []string {
	if !cloudEnabled() {
		return nil
	}
	ccMu.Lock()
	baseURL, token := cloudBaseURL, cloudToken
	ccMu.Unlock()
	resp, err := tursoPipeline(baseURL, token, []map[string]any{
		{
			"stmt": "SELECT k FROM ech_scan WHERE ts > :minTs",
			"args": map[string]any{"minTs": time.Now().Add(-24 * time.Hour).Unix()},
		},
	})
	if err != nil {
		return nil
	}
	var ips []string
	for _, r := range pipelineRows(resp, 0) {
		if len(r) > 0 {
			if s, ok := r[0].(string); ok && s != "" {
				ips = append(ips, s)
			}
		}
	}
	return ips
}

// tursoPipeline 调用 Turso v2 pipeline API（复用 LabelScanner 验证过的格式）。
func tursoPipeline(baseURL, token string, stmts []map[string]any) (map[string]any, error) {
	body, _ := json.Marshal(map[string]any{"statements": stmts})
	u := strings.TrimSuffix(baseURL, "/")
	if !strings.HasSuffix(u, "/v2/pipeline") {
		u += "/v2/pipeline"
	}
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// pipelineRows 提取 pipeline 响应的第 idx 个 statement 的 rows。
func pipelineRows(resp map[string]any, idx int) [][]any {
	results, _ := resp["results"].([]any)
	if idx >= len(results) {
		return nil
	}
	r, _ := results[idx].(map[string]any)
	rows, _ := r["rows"].([]any)
	out := make([][]any, 0, len(rows))
	for _, row := range rows {
		rr, _ := row.([]any)
		out = append(out, rr)
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}
