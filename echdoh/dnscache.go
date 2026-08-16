// DNS 解析结果缓存（2026-08-16）：治"等半天才响应"。
// 之前每次 DNS 查询都打 CF gateway 上游（大陆 300-800ms/次），
// 页面加载 N 个域名 = N 次海外往返。缓存最终响应（已改写/注入后），
// 重复查询直接返回，免上游。
package echdoh

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	respCacheMu sync.Mutex
	respCache   = map[string]respCacheEntry{}
)

type respCacheEntry struct {
	msg []byte // 打包好的最终响应（已强注/强改）
	ts  time.Time
}

// respCacheTTL 解析缓存时长：60s（改 IP 配置后 1 分钟内生效）。
const respCacheTTL = 60 * time.Second

// respCacheGet 取缓存（打包好的原始字节）。
func respCacheGet(key string) []byte {
	respCacheMu.Lock()
	defer respCacheMu.Unlock()
	if e, ok := respCache[key]; ok && time.Since(e.ts) < respCacheTTL {
		return e.msg
	}
	return nil
}

// respCachePut 写缓存。
func respCachePut(key string, msg []byte) {
	respCacheMu.Lock()
	respCache[key] = respCacheEntry{msg: msg, ts: time.Now()}
	respCacheMu.Unlock()
}

// respCacheKey 缓存键：域名|类型|override版本（override 变更后自动失效）
func respCacheKey(name string, qtype uint16) string {
	return name + "|" + dns.TypeToString[qtype]
}

// respCacheClear 清空（云配置刷新 override 变更时调用）。
func respCacheClear() {
	respCacheMu.Lock()
	respCache = map[string]respCacheEntry{}
	respCacheMu.Unlock()
	slog("dns resp cache cleared")
}
