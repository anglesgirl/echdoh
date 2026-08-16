// Package echdoh 将本地 DoH 注入服务器导出为 gomobile 库，
// 供 Android GeckoView 浏览器内嵌使用。
//
// 作用：监听 127.0.0.1:8443 HTTPS DoH，对所有域名无条件注入
// Cloudflare 公共 ECH 公钥（ech=），Firefox/GeckoView 配 TRR
// 指向本服务后原生 ECH 自动启用，SNI 隐藏，被墙站点可访问。
//
// 配套 DNS：doh.anglesgirl.eu.org → 127.0.0.1（CF 托管，全球生效，
// 任何设备解析都是本机回环，无需 root 改 hosts）。
// 证书：Let's Encrypt DNS-01 签发的 doh.anglesgirl.eu.org 合法证书，
// 浏览器验证域名证书通过，实际连接落在本机。
package echdoh

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/anglesgirl/echdoh/internal/cloudflare"
	"github.com/miekg/dns"
)

var (
	mu       sync.Mutex
	srv      *http.Server
	running  bool
	upstream []string
	// 手动 IP 覆盖（2026-08-15 用户要求）：域名=IP 强制改写 A 记录，
	// 不用等构建直接测试任意 IP（如 x.com=162.159.140.229）。
	overrideMu  sync.Mutex
	overrideMap = map[string]string{}
)

// SetOverride 设置域名→IP 强制覆盖（逗号/换行分隔多条："x.com=162.159.140.229"）。
// 支持多 IP："x.com=172.64.146.66,104.18.41.190"（A 记录返回多个，Firefox 挨个试）。
// 热更新：DNS 查询实时生效，无需重启。
func SetOverride(s string) {
	overrideMu.Lock()
	defer overrideMu.Unlock()
	overrideMap = map[string]string{}
	for _, line := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' }) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parts[0]), "."))
			ip := strings.TrimSpace(parts[1])
			if host != "" && ip != "" {
				overrideMap[host] = ip
			}
		}
	}
	slog("override set: %d rule(s)", len(overrideMap))
}

// matchOverride 精确或子域匹配（x.com 规则同时覆盖 api.x.com / abs.twimg.com 等）。
func matchOverride(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	overrideMu.Lock()
	defer overrideMu.Unlock()
	if ip, ok := overrideMap[name]; ok {
		return ip, true
	}
	for k, ip := range overrideMap {
		if strings.HasSuffix(name, "."+k) {
			return ip, true
		}
	}
	return "", false
}

var (
	lastErr  string
	logBuf   []string // Go 侧日志缓冲（Kotlin 轮询拉取）
	logBufMu sync.Mutex
	logPos   int
)

// PollLogs 增量返回 Go 侧日志（Kotlin 定时轮询写入 echbrowser.log）。
// gomobile 不支持导出 func 参数回调，用轮询替代。
func PollLogs() string {
	logBufMu.Lock()
	defer logBufMu.Unlock()
	if logPos >= len(logBuf) {
		return ""
	}
	out := ""
	for i := logPos; i < len(logBuf); i++ {
		out += logBuf[i] + "\n"
	}
	logPos = len(logBuf)
	return out
}

// slog 带缓冲的日志：既写 stderr（logcat），也进缓冲供 Kotlin 拉取。
func slog(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("[doh] %s", msg)
	logBufMu.Lock()
	logBuf = append(logBuf, msg)
	logBufMu.Unlock()
}

// Start 启动本地 DoH 注入服务器（127.0.0.1:listen）。
// certPEM/keyPEM 为合法域名证书（PEM 文本），upstreams 为逗号分隔的上游 DoH。
func Start(listen string, certPEM, keyPEM, upstreams string) error {
	mu.Lock()
	defer mu.Unlock()
	if running {
		return nil
	}
	if strings.TrimSpace(listen) == "" {
		listen = "127.0.0.1:8443"
	}
	upstream = nil
	// 2026-08-16：种子 TXT（ech-config.anglesgirl.eu.org doh=/doh2=/doh3=）
	// 动态上游优先（7 个 CF gateway 轮换，远端可改）；失败用传入的兜底
	if seed := fetchSeedUpstreams(); len(seed) > 0 {
		upstream = seed
	} else {
		for _, u := range strings.Split(upstreams, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				upstream = append(upstream, u)
			}
		}
	}
	if len(upstream) == 0 {
		upstream = []string{
			"https://pieqllv9i7.cloudflare-gateway.com/dns-query",
			"https://162.159.36.5/dns-query",
		}
	}
	slog("upstreams: %d endpoints", len(upstream))

	// 后台扫描 CF IP 段找可达边缘（进轮换池，解决单一 IP 抖动）
	StartScanCFIPs(64)

	// 云缓存：启动拉一次云端探测结果合并（SetCloudCache 启用时）
	go func() {
		time.Sleep(2 * time.Second) // 等本地缓存加载完
		cloudPull()
	}()

	// 云配置：从 doh.anglesgirl.eu.org TXT 拉取 overrides/force/pool
	// （2026-08-15 用户要求：改 IP 改 DNS 记录即可，零出包）
	StartCloudConfig()

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", handleDoH)
	// 管理后台（2026-08-16）：本机浏览器打开 https://doh.anglesgirl.eu.org:8443/admin
	mux.HandleFunc("/admin", handleAdmin)
	mux.HandleFunc("/admin/api/status", handleAdminStatus)
	mux.HandleFunc("/admin/api/logs", handleAdminLogs)
	mux.HandleFunc("/admin/api/refresh", handleAdminRefresh)

	// 用 PEM 内容直接构造 TLS 证书（ListenAndServeTLS 只接受文件路径，
	// gomobile 场景拿不到文件系统路径，必须 X509KeyPair 加载内容）。
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		mu.Lock()
		lastErr = "load cert: " + err.Error()
		mu.Unlock()
		return fmt.Errorf("load cert: %w", err)
	}

	s := &http.Server{
		Addr:    listen,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	srv = s
	running = true
	lastErr = ""

	go func() {
		defer func() {
			if r := recover(); r != nil {
				mu.Lock()
				lastErr = fmt.Sprintf("serve panic: %v", r)
				running = false
				mu.Unlock()
			}
		}()
		// 已用 X509KeyPair 加载证书。必须用 ListenAndServeTLS（自动创建
		// listener）；ServeTLS(nil,...) 传 nil listener 会 panic。
		if err := s.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			mu.Lock()
			lastErr = "serve: " + err.Error()
			running = false
			mu.Unlock()
		}
	}()
	return nil
}

// Stop 关闭服务器。安全可重复调用。
func Stop() error {
	mu.Lock()
	s := srv
	srv = nil
	running = false
	mu.Unlock()
	if s != nil {
		return s.Close()
	}
	return nil
}

// IsRunning 报告服务是否在运行。
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return running
}

// LastError 返回最近一次启动/运行错误。
func LastError() string {
	mu.Lock()
	defer mu.Unlock()
	return lastErr
}

func handleDoH(w http.ResponseWriter, r *http.Request) {
	queryCount++
	var raw []byte
	if r.Method == http.MethodGet {
		b64 := r.URL.Query().Get("dns")
		if b64 == "" {
			http.Error(w, "missing dns param", http.StatusBadRequest)
			return
		}
		var err error
		raw, err = base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			http.Error(w, "bad base64", http.StatusBadRequest)
			return
		}
	} else if r.Method == http.MethodPost {
		buf := make([]byte, 65535)
		n, err := r.Body.Read(buf)
		if err != nil && n == 0 {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		raw = buf[:n]
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}
	if len(req.Question) == 0 {
		http.Error(w, "no question", http.StatusBadRequest)
		return
	}
	q := req.Question[0]

	resp, err := queryUpstream(req)
	if err != nil {
		slog("upstream error for %s %s: %v", q.Name, dns.TypeToString[q.Qtype], err)
		writeError(w, req, dns.RcodeServerFailure)
		return
	}
	resp.Id = req.Id

	// 手动 IP 覆盖（最高优先，2026-08-15）：用户指定的 域名=IP 直接返回。
	// A 记录返回指定 IP；HTTPS 查询同样注入 ech= + ipv4hint=指定 IP ——
	// 2026-08-15 实测修复：旧代码只处理 A/AAAA，HTTPS 落到 forced-CF 分支
	// 注入的 hints 与 A 记录不一致，且用户指定 IP 若不在探测池里 Firefox
	// 会用明文 SNI 直连 → 被墙（loadError 0x93 NETWORK）。
	// 手动指定 IP + ECH 才能既用用户想要的 IP 又隐藏 SNI。
	// AAAA 覆盖域名清空（强制 IPv4）。
	if ip, ok := matchOverride(q.Name); ok {
		switch q.Qtype {
		case dns.TypeA:
			// 支持多 IP（逗号分隔）：返回多个 A 记录，Firefox 挨个试
			ips := strings.Split(ip, ",")
			var ans []dns.RR
			seen := map[string]bool{}
			for _, s := range ips {
				s = strings.TrimSpace(s)
				p := net.ParseIP(s)
				if p == nil || seen[s] {
					continue
				}
				seen[s] = true
				ans = append(ans, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   p,
				})
			}
			if len(ans) == 0 {
				// 非法 IP：返回空，别给 Firefox 无效地址
				slog("%s: OVERRIDE A -> invalid ip %q", q.Name, ip)
				resp.Answer = nil
			} else {
				resp.Answer = ans
				slog("%s: OVERRIDE A -> %v", q.Name, ips)
			}
		case dns.TypeAAAA:
			resp.Answer = nil
			slog("%s: OVERRIDE AAAA -> empty", q.Name)
		case dns.TypeHTTPS:
			// 注入 ech= + ipv4hint=override IP 列表：A 与 HTTPS 指向同一批 IP，
			// Firefox 走 ECH 隐藏 SNI（见 injectECHWithHints）。
			injectECHWithHints(resp, q.Name, strings.Split(ip, ","))
			slog("%s: OVERRIDE HTTPS -> ech= + hint=%s", q.Name, ip)
		}
		writeResponse(w, resp)
		return
	}

	// 强制改写名单：x.com 全家桶（已实测 CF 上有完整内容，DNS 轮询
	// 在 CF/Fastly 间切换，必须无条件强注强改，否则拿到 Fastly IP 时
	// 误判"非CF"放行 → 明文直连被墙）。
	if shouldForceCF(q.Name) {
		switch q.Qtype {
		case dns.TypeA:
			forceRewriteA(resp, q.Name)
		case dns.TypeAAAA:
			rewriteAAAAEmpty(resp, q.Name)
		case dns.TypeHTTPS:
			injectECHForced(resp, q.Name)
		}
		slog("%s %s -> %d answers (forced-CF)", q.Name, dns.TypeToString[q.Qtype],
			len(resp.Answer))
		// ⚠️ 2026-08-15 根因：这里原本直接 return，从未 Pack + Write ——
		// x.com 全家桶的 DoH 响应体为空（0 字节），Firefox TRR 解析失败，
		// trr.mode=3 无 Do53 回退 → loadError code=37。日志里
		// "x.com A -> 6 answers (forced-CF)" 只是内存里的答案，没发出去。
		// dohbench 实测：客户端收到 "overflow unpacking uint16"（空响应）。
		writeResponse(w, resp)
		return
	}

	if q.Qtype == dns.TypeHTTPS {
		injectECH(resp, q.Name)
	}
	// A 记录改写：若目标（跟随 CNAME）是 CF 托管但 IP 大陆被墙，
	// 替换为 DoH 端点 IP（162.159.36.x 实测可达）。
	if q.Qtype == dns.TypeA {
		rewriteAIfCF(resp, q.Name)
	}
	// AAAA 清空：CF 托管站点强制 IPv4（DoH 端点 IP），避免 Firefox
	// 优先 IPv6 超时。非 CF 站点原样保留。
	if q.Qtype == dns.TypeAAAA {
		if isCloudflareHosted(q.Name) {
			rewriteAAAAEmpty(resp, q.Name)
		}
	}

	slog("%s %s -> %d answers (%s)", q.Name, dns.TypeToString[q.Qtype],
		len(resp.Answer), summarizeECH(resp))

	writeResponse(w, resp)
}

// writeResponse 打包并写出 DNS 响应。所有出口必须走这里 —— 2026-08-15
// 的 code=37 根因就是 forced-CF 分支绕过了写响应的代码直接 return。
func writeResponse(w http.ResponseWriter, resp *dns.Msg) {
	out, err := resp.Pack()
	if err != nil {
		slog("pack failed: %v", err)
		http.Error(w, "pack failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "max-age=60")
	w.Write(out)
}

// queryUpstream 用 net/http 走 RFC 8484 GET（application/dns-message 二进制）。
func queryUpstream(req *dns.Msg) (*dns.Msg, error) {
	raw, err := req.Pack()
	if err != nil {
		return nil, err
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	var lastErr error
	for _, u := range upstream {
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		full := u + sep + "dns=" + b64
		resp, err := client.Get(full)
		if err != nil {
			lastErr = err
			lastUpstreamErr = fmt.Sprintf("%s %s: %v", time.Now().Format("15:04:05"), u, err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			lastUpstreamErr = fmt.Sprintf("%s %s: %v", time.Now().Format("15:04:05"), u, err)
			continue
		}
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("upstream HTTP %d", resp.StatusCode)
			lastUpstreamErr = fmt.Sprintf("%s %s: HTTP %d", time.Now().Format("15:04:05"), u, resp.StatusCode)
			continue
		}
		out := new(dns.Msg)
		if err := out.Unpack(body); err != nil {
			lastErr = err
			continue
		}
		return out, nil
	}
	return nil, lastErr
}

// svcbValues 从 HTTPS/SVCB 记录提取 SvcParam 键值列表。
// miekg/dns 对 type 65 的具体类型可能是 *dns.HTTPS 或 *dns.SVCB（同一结构）。
func svcbValues(rr dns.RR) []dns.SVCBKeyValue {
	if svcb, ok := rr.(*dns.SVCB); ok {
		return svcb.Value
	}
	if https, ok := rr.(*dns.HTTPS); ok {
		return https.Value
	}
	return nil
}

// injectECH 无条件注入 CF 公共 ECH 公钥。
//
// 策略（2026-08-14 修正）：只给 CF 托管域名（跟随 CNAME 链判断）注入。
// 理由：
//  1. CF 托管被墙站（x.com 等）靠注入隐藏 SNI —— 必须注入；
//  2. Fastly 托管（abs/cdn.syndication.twimg.com 等 CSS/JS 资源）**不能注入**：
//     Fastly 不认 CF 公共公钥 → ECH 握手失败 → Firefox 降级明文并缓存 24h
//     → 该域名整个废掉（用户实测页面 CSS 全丢）；
//  3. 非 CF 站点（baidu 等）同样不注入，避免多余 ECH 尝试。
func injectECH(resp *dns.Msg, name string) {
	name = dns.Fqdn(name)

	// 已有 ech= 就不用注入（尊重站点自己的配置）
	for _, rr := range resp.Answer {
		for _, kv := range svcbValues(rr) {
			if _, isECH := kv.(*dns.SVCBECHConfig); isECH {
				return
			}
		}
	}

	// 只给 CF 托管域名注入（跟随 CNAME 链判断，同 rewriteAIfCF）
	if !isCloudflareHosted(name) {
		slog("%s: not CF-hosted, skip inject", name)
		return
	}

	// 获取 CF 公共 ECH 公钥
	echConfig := fetchCFPublicECH()
	if len(echConfig) == 0 {
		slog("%s: no CF public ECH key available, skip inject", name)
		return
	}

	// 注入 ipv4hint=DoH 端点 IP：目标域自己的 A 记录（如 x.com 172.66.0.227）
	// 在大陆可能被墙，而 DoH 端点 IP（162.159.36.x）实测可达。RFC 9460
	// 规定客户端优先用 SVCB 的 ipv4hint 连接，从而绕开被墙边缘。
	hintIPs := fetchDohEndpointIPv4s()

	svcb := &dns.SVCB{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeHTTPS,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Priority: 1,
		Target:   ".",
		Value: []dns.SVCBKeyValue{
			&dns.SVCBECHConfig{ECH: echConfig},
			// ⚠️ 只留 http/1.1：xprobe CLI 实测 HTTP/1.1+ECH→200，
			// Firefox 用 h2+ECH 页面失败（CF 边缘 ECH+h2 组合异常）。
			&dns.SVCBAlpn{Alpn: []string{"http/1.1"}},
		},
	}
	if len(hintIPs) > 0 {
		hints := make([]net.IP, 0, len(hintIPs))
		for _, h := range hintIPs {
			if ip := net.ParseIP(h); ip != nil {
				hints = append(hints, ip)
			}
		}
		if len(hints) > 0 {
			svcb.Value = append(svcb.Value, &dns.SVCBIPv4Hint{Hint: hints})
		}
	}
	resp.Answer = append(resp.Answer, svcb)
	resp.Authoritative = true
	slog("injected ech= into HTTPS record for %s (%d bytes, hints=%v)", name, len(echConfig), hintIPs)
}

// isForceCF 判断域名是否属于"强制 CF"名单（x.com 全家桶）。
// 2026-08-14 实测：abs/pbs/video.twimg.com 的内容在 CF 上存在（真实
// 路径 200），但 DNS 在 CF/Fastly 间轮询——拿到 Fastly IP 时必须
// 无条件改写，否则直连 Fastly 明文被墙。名单随 x.com 迁移扩展。
func isForceCF(name string) bool {
	n := strings.ToLower(dns.Fqdn(name))
	n = strings.TrimSuffix(n, ".")
	if n == "x.com" || n == "twitter.com" {
		return true
	}
	if strings.HasSuffix(n, ".x.com") || strings.HasSuffix(n, ".twitter.com") ||
		strings.HasSuffix(n, ".twimg.com") {
		return true
	}
	return false
}

// tcpReachable TCP 443 可达性测试（connect 耗时 ≈ RTT，1s 超时）。
// 2026-08-15 echbrowser 实测：x.com 官方段 172.66.0.x 在移动宽带 TCP
// 层就超时（code=37）——不改写为可达 IP 时 Firefox 依次试 6 个全超时。
func tcpReachable(ip string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// echHandshakeCache ECH 握手测试结果缓存（域名+IP → 是否 ECH accepted）。
// false 结果只缓存 60s（2026-08-15 实测同一 IP 探测结果不稳定：网络抖动
// 时一次 false 会害死整段），true 缓存 10min。
// 2026-08-15 用户钦定 pool IP（TXT cloud config pool=）：true 结果缓存
// 24h 并落盘（echtest-cache.json），下次启动直接读缓存零探测 —— 除非
// 过期或用户改 pool 才重探。
var (
	echTestMu    sync.Mutex
	echTestCache = map[string]echTestEntry{}
	echTestPath  string
)

type echTestEntry struct {
	ok bool
	ts time.Time
}

// poolTrueTTL 钦定 pool IP 的 true 缓存时长（24h）。
const poolTrueTTL = 24 * time.Hour

// LoadEchTestCache 从文件加载 IP 级 ECH 探测缓存（App 启动时调用）。
// 过期条目丢弃。与域名级 probe-cache.json 分离（echtest-cache.json）。
func LoadEchTestCache(path string) {
	echTestMu.Lock()
	defer echTestMu.Unlock()
	echTestPath = path
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var m map[string]struct {
		OK bool  `json:"ok"`
		TS int64 `json:"ts"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return
	}
	now := time.Now()
	loaded := 0
	for k, v := range m {
		ts := time.Unix(v.TS, 0)
		ttl := time.Hour
		if v.OK {
			// true 统一 24h（2026-08-15：不只 pool IP，所有 ECH 探测
			// 通过的 IP 都落盘 —— 冷启动 x.com 全家桶免全量重探）
			ttl = poolTrueTTL
		} else {
			// false 也落盘缓存 1h（abs-0 全 false 结果不落盘 →
			// 冷启动每次重探 8 IP 浪费 12 秒才跳转）
			ttl = time.Hour
		}
		if now.Sub(ts) > ttl {
			continue
		}
		echTestCache[k] = echTestEntry{ok: v.OK, ts: ts}
		loaded++
	}
	slog("ech test cache loaded: %d entries from %s", loaded, path)
}

// SaveEchTestCache 持久化 IP 级 ECH 探测缓存。
func SaveEchTestCache() {
	echTestMu.Lock()
	defer echTestMu.Unlock()
	if echTestPath == "" {
		return
	}
	m := map[string]struct {
		OK bool  `json:"ok"`
		TS int64 `json:"ts"`
	}{}
	for k, v := range echTestCache {
		m[k] = struct {
			OK bool  `json:"ok"`
			TS int64 `json:"ts"`
		}{v.ok, v.ts.Unix()}
	}
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	if err := os.WriteFile(echTestPath, data, 0644); err != nil {
		slog("ech test cache save failed: %v", err)
	}
}

// echHandshakeOK 对候选 IP 做完整 ECH 握手测试（TCP + ClientHello 带 CF
// 公共 ECH 公钥），只认 ECHAccepted=true。2026-08-15 用户 xprobe 实测
// 决定性证据：x.com 官方段 162.159.140.x ECH accepted → HTTP 200（1.5s），
// 而同段 172.66.0.x ECH 握手挂起（echbrowser Firefox code=37 超时）——
// 官方解析多段中部分段不响应 ECH。必须探测后只改写到 ECH 可用的段。
// hasOwnECHConfig 查上游 HTTPS 记录：域名是否自带 ech= 配置。
// 2026-08-16：javchu.com 等发布 CF 公共 ECH 的域名，probe 时 inner cert
// 是 cloudflare-ech.com（不匹配域名）—— 但 Firefox 用域名自己发布的 ech=
// 连接，接受该证书，必须算 forceable（否则 A 记录不改写 → 官方 IP 路由到
// 远边缘，实测 javchu.com → AMS）。
func hasOwnECHConfig(name string) bool {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeHTTPS)
	resp, err := queryUpstream(q)
	if err != nil || resp == nil {
		return false
	}
	for _, rr := range resp.Answer {
		for _, kv := range svcbValues(rr) {
			if _, isECH := kv.(*dns.SVCBECHConfig); isECH {
				return true
			}
		}
	}
	return false
}

func echHandshakeOK(ip, host string, timeout time.Duration) bool {
	cacheKey := host + "|" + ip
	echTestMu.Lock()
	if e, ok := echTestCache[cacheKey]; ok {
		// 与 LoadEchTestCache 一致的 TTL：true 24h（poolTrueTTL）、
		// false 1h。2026-08-16 bug：这里原用 true 10min / false 60s，
		// 落盘加载的条目（24h 收进内存）读取时全被判过期 → 冷启动
		// 每次都全量重探（00:12 日志 x.com 探测 10 个 IP 12 秒）。
		ttl := time.Hour
		if e.ok {
			ttl = poolTrueTTL
		}
		if time.Since(e.ts) < ttl {
			echTestMu.Unlock()
			return e.ok
		}
	}
	echTestMu.Unlock()
	ok := func() bool {
		d := &net.Dialer{Timeout: timeout}
		conn, err := d.Dial("tcp", net.JoinHostPort(ip, "443"))
		if err != nil {
			return false
		}
		defer conn.Close()
		ech := fetchCFPublicECH()
		if len(ech) == 0 {
			slog("%s: no CF public ECH key, skip ECH probe for %s", host, ip)
			return false
		}
		cfg := &tls.Config{
			ServerName:                     host,
			MinVersion:                     tls.VersionTLS13,
			NextProtos:                     []string{"http/1.1"},
			EncryptedClientHelloConfigList: ech,
		}
		tc := tls.Client(conn, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := tc.HandshakeContext(ctx); err != nil {
			return false
		}
		return tc.ConnectionState().ECHAccepted
	}()
	echTestMu.Lock()
	echTestCache[cacheKey] = echTestEntry{ok: ok, ts: time.Now()}
	// 2026-08-16：写后即落盘（原只在 pool 分支 Save → 官方段探测结果
	// 丢了，下次启动重探）。限频：最多 1s 一次，避免高频探测刷盘。
	entry := echTestCache[cacheKey]
	echTestMu.Unlock()
	saveEchTestCacheThrottled()
	cloudNote(cacheKey, entry) // 云缓存增量（20s 批量推送）
	slog("%s %s: ECH probe -> %v", host, ip, ok)
	return ok
}

// saveEchTestCacheThrottled 限频落盘（1s 内最多一次）。
var (
	saveThrottleMu sync.Mutex
	lastSaveTs     time.Time
)

func saveEchTestCacheThrottled() {
	saveThrottleMu.Lock()
	defer saveThrottleMu.Unlock()
	if time.Since(lastSaveTs) < time.Second {
		return
	}
	lastSaveTs = time.Now()
	SaveEchTestCache()
}

// officialSubnetIPs 从官方解析 CF IP 生成候选，全部经过 ECH 握手探测：
// 官方 IP 优先（ECH accepted 才用），再从官方 IP 的 /24 段随机采样补足。
// 官方段整体 ECH 不可用（如 x.com 172.66.0.x 挂起）时返回空 → 调用方
// 回退 DoH 端点/扫描池 IP。
func officialSubnetIPs(official []string, name string, max int) []string {
	var out []string
	seen := map[string]bool{}
	add := func(ip string) bool {
		if seen[ip] {
			return false
		}
		seen[ip] = true
		out = append(out, ip)
		return len(out) >= max
	}
	// 1. 官方 IP 并发 ECH 探测（~1.5s 并行完成，2026-08-15 修复：串行
	//    探测 45s 才完成，期间 A 记录为空 → Firefox 立即 loadError）
	type res struct {
		ip string
		ok bool
	}
	ch := make(chan res, len(official))
	for _, ip := range official {
		go func(ip string) {
			// 3s 超时（2026-08-15 修复：xprobe 实测 x.com ECH 握手
			// 1.519s，原 1.5s 超时卡边，抖动即 false；并发探测总耗时不变）
			ch <- res{ip, echHandshakeOK(ip, name, 3*time.Second)}
		}(ip)
	}
	var reachable []string
	for range official {
		r := <-ch
		if r.ok {
			reachable = append(reachable, r.ip)
		}
	}
	// 2. 第一个 ECH 可用官方 IP 的 /24 段随机采样（并发探测补足）
	if len(reachable) > 0 {
		for _, ip := range reachable {
			if add(ip) {
				return out
			}
		}
		v4 := net.ParseIP(reachable[0]).To4()
		if v4 != nil {
			rng := rand.New(rand.NewSource(time.Now().UnixNano()))
			var cand []int
			for i := 1; i < 255; i++ {
				cand = append(cand, i)
			}
			rng.Shuffle(len(cand), func(i, j int) { cand[i], cand[j] = cand[j], cand[i] })
			// 采样最多 6 个并发探测；**第一个 ok 立即返回**（2026-08-16
			// 用户要求：有一个可用直接用，后续没必要测 —— 不等满 max，
			// 冷启动从 ~12s 压到 ~2s）
			limit := 6
			if limit > len(cand) {
				limit = len(cand)
			}
			type sres struct {
				ip string
				ok bool
			}
			sch := make(chan sres, limit)
			launched := 0
			for _, i := range cand[:limit] {
				ip := net.IPv4(v4[0], v4[1], v4[2], byte(i)).String()
				if seen[ip] {
					continue
				}
				launched++
				go func(ip string) {
					sch <- sres{ip, echHandshakeOK(ip, name, 3*time.Second)}
				}(ip)
			}
			// 第一个成功即返回（其余 goroutine 写完 chan 后自然退出，
			// 结果丢弃 —— 探测是幂等的，缓存已写）
			for range launched {
				s := <-sch
				if s.ok && !seen[s.ip] {
					add(s.ip)
					return out
				}
			}
		}
	}
	return out
}

// containsStr 判断列表是否含某字符串（cloudconfig.go 也有一个，
// 这里复用同包定义 —— 若重复定义编译会报，保持单定义）。
func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ── 强制改写候选 IP：A 记录与 HTTPS ipv4hint 共用同一批 ──────────────
//
// 2026-08-15 根因：forceRewriteA 在 ECH 探测全失败时回退「原始官方 IP」
// （x.com 172.66.0.227 / 162.159.140.229），而那批 IP 正是刚被探测判定
// ECH 不可用的 —— Firefox 只拿到 1 个 A 记录 → TCP/TLS 超时 → code=37。
// 同时 HTTPS 记录的 ipv4hint 用 fetchDohEndpointIPv4s()（实测可达池），
// 与 A 记录不是同一批，两条路径连不同 IP。
//
// 修复：统一走 forcedHintIPs()，三级兜底且绝不回退到探测失败的官方 IP：
//  1. 官方 IP + 其 /24 段中 ECH 握手成功的（officialSubnetIPs）
//  2. 官方段整体 ECH 不可用 → 从可达池里挑 ECH 握手成功的
//  3. 全失败 → 可达池原样（宁可给「可达但未验证」，绝不给「已知不可达」）
var (
	forcedHintMu     sync.Mutex
	forcedHintCache  = map[string]forcedHintEntry{}
	forcedHintFlight = map[string]*sync.WaitGroup{} // 单飞：A/HTTPS 并发查询只探测一次
)

type forcedHintEntry struct {
	ips []string
	ts  time.Time
}

const forcedHintTTL = 5 * time.Minute

// forcedHintIPs 返回域名强制改写用的 IP 列表（最多 max 个）。
// official 为该域名官方解析出的 CF IP；传 nil 时（HTTPS 查询场景，
// 响应里没有 A 记录）内部自己做一次上游 A 查询补齐。
//
// 单飞保护：Firefox 会几乎同时发 A / AAAA / HTTPS 三个查询，若各自独立
// 探测会重复几十次 TLS 握手（旧日志里同一秒重复三遍 ECH probe 即此因）。
func forcedHintIPs(name string, official []string, max int) []string {
	return forcedHintIPsOpt(name, official, max, false)
}

// forcedHintIPsOpt：poolFirst=true 时 pool IP（ECH 验证过的）排最前。
// 2026-08-16：非 forced 域名（rewriteAIfCF 路径）pool 优先 —— 用户实测
// javchu.com 官方段 IP 路由到 AMS（欧洲，~200ms），而 pool 钦定 IP
// （172.64.146.66/104.18.41.190）实测路由 NRT（东京）快；forced 名单
// （x.com）保持官方段优先（2026-08-15 教训：pool 排第 1 时 0x93 失败）。
func forcedHintIPsOpt(name string, official []string, max int, poolFirst bool) []string {
	key := strings.TrimSuffix(strings.ToLower(dns.Fqdn(name)), ".")

	for {
		forcedHintMu.Lock()
		if e, ok := forcedHintCache[key]; ok && time.Since(e.ts) < forcedHintTTL {
			// 命中即返回，包括负缓存（ips 为 nil 的 fail-closed 结果）。
			// 2026-08-15：旧代码 len(e.ips)>0 才算命中，abs-0 探测全失败
			// 返回 nil 后不写缓存，导致每次 DNS 查询都重探 16 个 IP
			// （日志 21:07:41→56 重探十几次）。
			forcedHintMu.Unlock()
			return e.ips
		}
		if wg, inflight := forcedHintFlight[key]; inflight {
			forcedHintMu.Unlock()
			wg.Wait() // 等别人探测完，回头读缓存
			continue
		}
		wg := &sync.WaitGroup{}
		wg.Add(1)
		forcedHintFlight[key] = wg
		forcedHintMu.Unlock()
		defer func() {
			forcedHintMu.Lock()
			delete(forcedHintFlight, key)
			forcedHintMu.Unlock()
			wg.Done()
		}()
		break
	}

	if len(official) == 0 {
		official = lookupOfficialCFIPv4s(name)
	}

	var out []string
	src := ""

	// 0. 云配置 pool IP（用户钦定）：探测结果缓存 24h 免重探，但**只作为
	// 备胎放列表末尾** —— 2026-08-15 实测：172.64.146.66（wto.org 段）
	// 对 x.com Go 探测 ECH true，但 Firefox 实际连接 0x93 NETWORK 失败
	// （22:45 该 IP 排第 3 时成功，23:16 排第 1 时失败）。探测 true ≠
	// Firefox 可用，必须让已验证的官方段 IP 排前面。
	var poolOut []string
	// 2026-08-16：pool IP 并发探测（原串行最坏 6s → 并发最多 3s）
	poolIPs := cloudPoolIPs()
	type pres struct {
		ip string
		ok bool
	}
	pch := make(chan pres, len(poolIPs))
	for _, ip := range poolIPs {
		go func(ip string) {
			echTestMu.Lock()
			e, cached := echTestCache[name+"|"+ip]
			echTestMu.Unlock()
			if cached {
				pch <- pres{ip, e.ok && time.Since(e.ts) < poolTrueTTL}
				return
			}
			// 无缓存：探测一次，结果落盘（后续 24h 免探）
			pch <- pres{ip, echHandshakeOK(ip, name, 3*time.Second)}
		}(ip)
	}
	for range poolIPs {
		r := <-pch
		if r.ok && !containsStr(poolOut, r.ip) {
			poolOut = append(poolOut, r.ip)
		}
	}
	if len(poolOut) > 0 {
		SaveEchTestCache()
		src = "cloud-pool(ECH-cached)"
	}

	// poolFirst（非 forced 域名）：pool IP 先入 out（最前），official 补充在后面
	if poolFirst && len(poolOut) > 0 {
		for _, ip := range poolOut {
			if !containsStr(out, ip) {
				out = append(out, ip)
			}
			if len(out) >= max {
				break
			}
		}
		src = "cloud-pool(ECH-cached,first)"
	}

	if len(official) > 0 {
		if ips := officialSubnetIPs(official, name, max); len(ips) > 0 {
			// pool IP 备胎在末尾，official 探测结果优先（2026-08-15）
			src = "official-subnet(ECH-probed)"
			for _, ip := range ips {
				if !containsStr(out, ip) {
					out = append(out, ip)
				}
				if len(out) >= max {
					break
				}
			}
		}
	}
	// 官方段 ECH 全挂 → 可达池里挑 ECH 握手成功的（xprobe 实测 162.159.36.x
	// 这类 CF 边缘 inner-SNI=x.com 的 ECH 握手成功 → HTTP 200）
	pool := fetchDohEndpointIPv4s()
	if len(out) < max && len(pool) > 0 {
		// 探测 8 个（2026-08-15 优化：原 16 个，手机日志实测探测太多
		// 浪费 —— 8 个足够，池子 IP 冗余度高）
		if ips := echFilterPool(pool, name, max, 8); len(ips) > 0 {
			src = "reachable-pool(ECH-probed)"
			for _, ip := range ips {
				if !containsStr(out, ip) {
					out = append(out, ip)
				}
				if len(out) >= max {
					break
				}
			}
		}
	}
	// 2026-08-16：非 forced 域名 pool 优先（poolFirst）—— 官方段 IP 可能
	// 路由到远边缘（javchu.com→AMS 实测），pool 钦定 IP 实测路由 NRT 快。
	if poolFirst && len(poolOut) > 0 {
		for _, ip := range poolOut {
			if !containsStr(out, ip) {
				out = append(out, ip)
			}
			if len(out) >= max {
				break
			}
		}
		src = "cloud-pool(ECH-cached,first)"
	}
	// 最后补 pool 备胎（不占已验证 IP 的位置）
	if len(out) < max {
		for _, ip := range poolOut {
			if !containsStr(out, ip) {
				out = append(out, ip)
			}
			if len(out) >= max {
				break
			}
		}
	}
	// ⚠️ 没有第三级「可达池原样」兜底 —— fail-closed。
	//
	// 2026-08-15 abs-0.twimg.com 实测：官方段 + 可达池共 16 个 IP 的 ECH
	// 探测全部 false。xprobe 单独验证：连 CF 边缘直接
	// `remote error: tls: handshake failure`，连官方 IP 则证书是
	// *.twimg.com 而非 cloudflare-ech.com —— **CF 上根本没有这个域名的
	// 配置**（它走 Fastly：x-tw-cdn: FT，CNAME abs-zero.twimg.com →
	// 104.244.43.131 Twitter 自有段）。
	//
	// 旧代码此时塞 6 个无关 CF IP，ECH 必然失败；而回退原始解析等于
	// 明文 SNI 直连被墙 CDN —— 两条路都错。用户拍板：宁可资源加载失败，
	// 绝不暴露 SNI。返回 nil → 调用方给空 A 记录（fail-closed，
	// 与 AGENTS.md 1.3.3 种子兜底同原则）。
	//
	// 判据是**探测结果本身**，不是「域名在不在 CF」：abs/pbs.twimg.com
	// 的 DNS 同样指向 Fastly，但 CF 边缘用 cloudflare-ech.com 证书接受
	// ECH（探测 true）→ 强改成立。同一 *.twimg.com 通配下两种结果，
	// 只能靠探测区分。规则统一后，X 换域名不需要改代码。
	if len(out) == 0 {
		slog("%s: ECH probe failed on all candidates (official=%v) "+
			"-> CF 无此域名配置，返回空 A（fail-closed，不暴露 SNI）", name, official)
		// 负结果也写缓存：否则每次查询都重探（abs-0 实测日志里 16 个 IP
		// 反复探测十几次）。域名在 CF 的配置不会频繁变化，5min 足够。
		forcedHintMu.Lock()
		forcedHintCache[key] = forcedHintEntry{ips: nil, ts: time.Now()}
		forcedHintMu.Unlock()
		return nil
	}

	forcedHintMu.Lock()
	forcedHintCache[key] = forcedHintEntry{ips: out, ts: time.Now()}
	forcedHintMu.Unlock()
	slog("%s: forced hint IPs <- %s %v", name, src, out)
	return out
}

// echFilterPool 从候选池并发挑出 ECH 握手成功的 IP（最多 max 个，
// 最多探测 probeLimit 个候选，避免池子大时启动几十个 goroutine）。
func echFilterPool(pool []string, name string, max, probeLimit int) []string {
	cands := pool
	if len(cands) > probeLimit {
		cands = cands[:probeLimit]
	}
	type res struct {
		ip string
		ok bool
	}
	ch := make(chan res, len(cands))
	for _, ip := range cands {
		go func(ip string) {
			ch <- res{ip, echHandshakeOK(ip, name, 3*time.Second)}
		}(ip)
	}
	var out []string
	// 2026-08-16：第一个 ok 即返回（用户要求：一个可用直接用），
	// 其余 goroutine 写完 chan 自然退出（幂等，缓存已写）
	for range cands {
		r := <-ch
		if r.ok {
			out = append(out, r.ip)
			return out
		}
	}
	return out
}

// lookupOfficialCFIPv4s 上游查一次 A 记录，提取官方解析的 CF IP。
// HTTPS 查询时响应里没有 A 记录，需要单独查以便复用同一批候选。
func lookupOfficialCFIPv4s(name string) []string {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	resp, err := queryUpstream(q)
	if err != nil || resp == nil {
		return nil
	}
	return officialCFIPv4s(resp)
}

// officialCFIPv4s 从响应中提取官方解析的 CF（AS13335）IPv4（未改写前的原始值）。
func officialCFIPv4s(resp *dns.Msg) []string {
	var out []string
	seen := map[string]bool{}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			s := a.A.String()
			if !seen[s] && cloudflare.IsAS13335(s) {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// forceRewriteA 把 A 记录改写为 forcedHintIPs()（ECH 已验证的 CF 边缘）。
//
// forcedHintIPs 返回空 = 所有候选 ECH 探测失败 = CF 上没有该域名配置。
// 此时**清空 A 记录**（fail-closed），不保留原始解析 —— 保留就等于让
// Firefox 明文 SNI 直连该域名的真实 CDN（如 abs-0.twimg.com → Fastly），
// SNI 泄漏。用户拍板：宁可资源加载失败，绝不暴露 SNI。
func forceRewriteA(resp *dns.Msg, name string) {
	hintIPs := forcedHintIPs(name, officialCFIPv4s(resp), 6)
	newAnswers := make([]dns.RR, 0, len(hintIPs))
	for _, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.A, *dns.CNAME:
			continue
		default:
			newAnswers = append(newAnswers, rr)
		}
	}
	if len(hintIPs) == 0 {
		// 原 A/CNAME 已被丢弃，这里不补任何 A → 空答案（NODATA）。
		resp.Answer = newAnswers
		slog("%s: A cleared (ECH unavailable on CF, fail-closed 防 SNI 泄漏)", name)
		return
	}
	seen := map[string]bool{}
	added := 0
	for _, ip := range hintIPs {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		// 限 6 个：18 个 IP 会让 Firefox 依次试不完（每个超时 2-3s）
		// 就 loadError 了；6 个内快速试完，打不开的换下一个。
		if added >= 6 {
			break
		}
		added++
		newAnswers = append(newAnswers, &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(ip),
		})
	}
	resp.Answer = newAnswers
	slog("%s: FORCED A -> %v (%d)", name, hintIPs[:min(added, len(hintIPs))], added)
}

// injectECHForced 无条件注入 CF 公共 ECH 公钥（不判断是否 CF 托管）。
func injectECHForced(resp *dns.Msg, name string) {
	// ipv4hint 与 A 记录用同一批候选（forcedHintIPs），避免两条路径连
	// 不同 IP：A 记录给 ECH 已验证 IP、hint 给可达池 → Firefox 行为不定。
	hintIPs := forcedHintIPs(name, nil, 6)
	injectECHWithHints(resp, name, hintIPs)
}

// injectECHWithHints 用指定 hint IPs 注入 CF 公共 ECH 公钥。
// hintIPs 为空（ECH 探测全失败 / 无候选）时清空 HTTPS 记录（fail-closed，
// 与 forceRewriteA 一致 —— 见 forcedHintIPs 注释）。
func injectECHWithHints(resp *dns.Msg, name string, hintIPs []string) {
	for _, rr := range resp.Answer {
		for _, kv := range svcbValues(rr) {
			if _, isECH := kv.(*dns.SVCBECHConfig); isECH {
				return // 已有 ech= 不动
			}
		}
	}
	echConfig := fetchCFPublicECH()
	if len(echConfig) == 0 {
		slog("%s: no CF public ECH key available, skip forced inject", name)
		return
	}
	if len(hintIPs) == 0 {
		// ECH 探测全失败 = CF 无此域名配置。注入 ech= 只会让 Firefox 拿着
		// 无效配置去握手；A 记录那边已 fail-closed 清空，这里同样不注入，
		// 保持两条路径一致（见 forceRewriteA / forcedHintIPs 注释）。
		resp.Answer = nil
		slog("%s: HTTPS cleared (ECH unavailable on CF, fail-closed 防 SNI 泄漏)", name)
		return
	}
	svcb := &dns.SVCB{
		Hdr:      dns.RR_Header{Name: name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
		Priority: 1,
		Target:   ".",
		Value: []dns.SVCBKeyValue{
			&dns.SVCBECHConfig{ECH: echConfig},
			&dns.SVCBAlpn{Alpn: []string{"http/1.1"}},
		},
	}
	hints := make([]net.IP, 0, 6)
	for _, h := range hintIPs {
		if ip := net.ParseIP(h); ip != nil {
			hints = append(hints, ip)
			if len(hints) >= 6 {
				break
			}
		}
	}
	if len(hints) > 0 {
		svcb.Value = append(svcb.Value, &dns.SVCBIPv4Hint{Hint: hints})
	}
	resp.Answer = []dns.RR{svcb}
	slog("FORCED ech= into HTTPS record for %s (%d bytes, hints=%v)", name, len(echConfig), hintIPs[:min(6, len(hintIPs))])
}

// isCloudflareHosted 跟随 CNAME 链（≤5 跳）查询目标 A 记录，判断是否
// 全部为 CF 边缘（AS13335）。用于 injectECH 决定是否注入（Fastly 等
// 非 CF 域名不注入，避免 ECH 失败降级明文缓存 24h）。
func isCloudflareHosted(name string) bool {
	cur := dns.Fqdn(name)
	for hop := 0; hop < 5; hop++ {
		q := new(dns.Msg)
		q.SetQuestion(cur, dns.TypeA)
		r, err := queryUpstream(q)
		if err != nil {
			return false
		}
		var ips []string
		cur = ""
		for _, rr := range r.Answer {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, v.A.String())
			case *dns.CNAME:
				cur = dns.Fqdn(v.Target)
			}
		}
		if len(ips) > 0 {
			return cloudflare.AllAS13335(ips)
		}
		if cur == "" {
			return false
		}
	}
	return false
}

// rewriteAIfCF 若目标域名（跟随 CNAME 链）最终解析到 CF 边缘（AS13335），
// 则把 A 记录改写为 DoH 端点 IP（162.159.36.x，大陆实测可达）。
//
// 覆盖 x.com 全家桶：api.x.com / video.twimg.com(.cdn.cloudflare.net) 等
// 响应只有 CNAME 的域名也跟随判断，避免漏改导致 Firefox 直连被墙边缘。
func rewriteAIfCF(resp *dns.Msg, name string) {
	var ips []string
	var cname string
	for _, rr := range resp.Answer {
		switch r := rr.(type) {
		case *dns.A:
			ips = append(ips, r.A.String())
		case *dns.CNAME:
			cname = r.Target
		}
	}

	// 无 A 但有 CNAME：跟随 CNAME 再查（最多 5 跳）
	hops := 0
	cur := cname
	for len(ips) == 0 && cur != "" && hops < 5 {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(cur), dns.TypeA)
		r2, err := queryUpstream(q)
		if err != nil {
			break
		}
		cur = ""
		for _, rr := range r2.Answer {
			switch r := rr.(type) {
			case *dns.A:
				ips = append(ips, r.A.String())
			case *dns.CNAME:
				cur = r.Target
			}
		}
		hops++
	}
	if len(ips) == 0 {
		slog("%s: no A records (cname=%s), keep as-is", name, cname)
		return
	}
	if !cloudflare.AllAS13335(ips) {
		slog("%s: A=%v not CF (cname=%s), keep original", name, ips, cname)
		return
	}

	// 2026-08-15: 走 forcedHintIPs 复用 5min 结果缓存 + 单飞。
	//
	// 旧代码直接调 officialSubnetIPs()，该函数无结果缓存 —— 手机日志实测
	// challenges.cloudflare.com（CF 人机验证窗口）每次 DNS 查询都重探
	// 40+ 个 172.64.146.x，20:29:19/21/30/58、20:30:00 反复重复，验证窗口
	// 因此明显变慢。另外兜底 fetchDohEndpointIPv4s() 未截断，曾一次吐出
	// 32 条 A 记录，Firefox 要挨个试。
	//
	// forcedHintIPs 同时带来 fail-closed 语义：ECH 探测全失败 → 返回空 →
	// 这里保持原样不改写（本函数只在 AllAS13335 为真时才走到，域名确实在
	// CF 上，与 abs-0.twimg.com 那类不同，保留原始解析不会泄漏到墙外 CDN）。
	hintIPs := forcedHintIPsOpt(name, ips, 6, true) // 非 forced：pool 优先（NRT 快）
	if len(hintIPs) == 0 {
		slog("%s: ECH probe failed on all candidates, keep original A=%v", name, ips)
		return
	}
	newAnswers := make([]dns.RR, 0, len(resp.Answer)+len(hintIPs))
	for _, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.A, *dns.CNAME:
			continue // 丢弃原 A/CNAME
		default:
			newAnswers = append(newAnswers, rr)
		}
	}
	seen := map[string]bool{}
	for _, ip := range hintIPs {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		newAnswers = append(newAnswers, &dns.A{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP(ip),
		})
	}
	resp.Answer = newAnswers
	slog("%s: CF-hosted (cname=%s) A=%v -> rewritten to %v", name, cname, ips, hintIPs)
}

// rewriteAAAAEmpty 对 CF 托管域名返回空 AAAA（NODATA），强制 Firefox 走
// IPv4（改写的 DoH 端点 IP），避免等待 IPv6 超时。
func rewriteAAAAEmpty(resp *dns.Msg, name string) {
	if len(resp.Answer) == 0 {
		return
	}
	slog("%s: AAAA cleared (force IPv4)", name)
	resp.Answer = nil
}

// fetchDohEndpointIPv4s 解析 DoH 端点域名（如 pieqllv9i7.cloudflare-gateway.com）
// 的 IPv4，作为注入记录的 ipv4hint。这些 IP 是 CF 边缘，实测大陆可达。
// 解析失败时用内置快照兜底（同一批网关的已知 IP）。
func fetchDohEndpointIPv4s() []string {
	var ips []string
	seen := map[string]bool{}
	add := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip != "" && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}

	// 优先级：用户实测 12 个（最可信）> 云配置 pool > 扫描池 > 内置快照
	// 用户 2026-08-14 大陆实测可达列表（Firefox 会先试这些）
	// 云配置 pool（2026-08-15：远程 TXT 下发优选 IP，如 wto.org 段 172.64.146.66）
	for _, ip := range cloudPoolIPs() {
		add(ip)
	}
	for _, ip := range []string{
		"104.17.16.197", "104.19.43.13", "104.19.2.117",
		"172.64.52.66", "108.162.193.202", "172.64.53.55",
		"162.159.45.255", "162.159.38.37", "172.64.229.216",
		"162.159.44.0", "108.162.198.221", "162.159.39.151",
	} {
		add(ip)
	}
	// 扫描池（启动时随机扫到的可达 CF IP）
	for _, ip := range reachableCFIPs() {
		add(ip)
	}

	// 从 upstream DoH 域名解析 A 记录
	for _, u := range upstream {
		host := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
		if i := strings.Index(host, "/"); i >= 0 {
			host = host[:i]
		}
		if net.ParseIP(host) != nil {
			continue // 已经是 IP 直连（如 162.159.36.5）
		}
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(host), dns.TypeA)
		resp, err := queryUpstream(q)
		if err != nil {
			continue
		}
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				add(a.A.String())
			}
		}
	}

	// 内置快照兜底：多 IP 候选（大陆可达性不稳定，单一 IP 会全挂）。
	// 前 6 个为 DoH 网关/历史实测；其余 12 个为用户 2026-08-14 大陆实测可达。
	for _, ip := range []string{
		"162.159.36.5", "162.159.36.20", "162.159.140.229",
		"172.64.150.129", "104.18.37.127", "104.20.28.232",
		// 用户实测可达列表（2026-08-14）
		"104.17.16.197", "104.19.43.13", "104.19.2.117",
		"172.64.52.66", "108.162.193.202", "172.64.53.55",
		"162.159.45.255", "162.159.38.37", "172.64.229.216",
		"162.159.44.0", "108.162.198.221", "162.159.39.151",
	} {
		add(ip)
	}
	return ips
}

// fetchCFPublicECH 获取 Cloudflare 公共 ECH 公钥（cloudflare-ech.com HTTPS ech=）。
// echKeyMu/echKeyCache: CF 公共 ECH 配置缓存（2026-08-16 优化：
// 原每次调用都查上游 DoH —— 每个域名探测/响应各拉一次，浪费。
// cloudflare-ech.com 的配置长期不变，缓存 10min 足够）。
var (
	echKeyMu    sync.Mutex
	echKeyCache []byte
	echKeyTs    time.Time
)

func fetchCFPublicECH() []byte {
	echKeyMu.Lock()
	if len(echKeyCache) > 0 && time.Since(echKeyTs) < 10*time.Minute {
		echKeyMu.Unlock()
		return echKeyCache
	}
	echKeyMu.Unlock()
	q := new(dns.Msg)
	q.SetQuestion("cloudflare-ech.com.", dns.TypeHTTPS)
	resp, err := queryUpstream(q)
	if err != nil {
		slog("fetchCFPublicECH upstream error: %v", err)
		return nil
	}
	var ech []byte
	for _, rr := range resp.Answer {
		for _, kv := range svcbValues(rr) {
			if e, ok := kv.(*dns.SVCBECHConfig); ok {
				ech = e.ECH
			}
		}
	}
	if len(ech) > 0 {
		echKeyMu.Lock()
		echKeyCache = ech
		echKeyTs = time.Now()
		echKeyMu.Unlock()
	}
	return ech
}

func summarizeECH(resp *dns.Msg) string {
	for _, rr := range resp.Answer {
		for _, kv := range svcbValues(rr) {
			if ech, ok := kv.(*dns.SVCBECHConfig); ok {
				return fmt.Sprintf("ech=%dbytes", len(ech.ECH))
			}
		}
	}
	return "no-ech"
}

func writeError(w http.ResponseWriter, req *dns.Msg, rcode int) {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	out, _ := resp.Pack()
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(out)
}

var _ = net.ParseIP
var _ = os.Exit
