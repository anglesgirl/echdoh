// 域名可强改探测缓存：首次访问某域名时，后台尝试连 CF 边缘 + ECH，
// TLS 证书验证成功 = CF 上有该域名内容 = 可强改。结果持久化，下次直接查。
package echdoh

import (
	"crypto/x509"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/anglesgirl/echdoh/internal/cloudflare"
	"github.com/anglesgirl/echdoh/internal/dns"
	"github.com/anglesgirl/echdoh/internal/tlsconn"
	mdns "github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
)

var (
	probeMu     sync.Mutex
	probeCache  map[string]bool // name -> 可强改
	probePath   string          // 缓存文件路径
	probeProbe  map[string]bool // 正在探测中的域名
	probeDohIPs []string        // 探测用的 CF 边缘 IP
)

func init() {
	probeCache = map[string]bool{}
	probeProbe = map[string]bool{}
}

// LoadProbeCache 从文件加载缓存（App 启动时调用）。
func LoadProbeCache(path string) {
	probeMu.Lock()
	defer probeMu.Unlock()
	probePath = path
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var m map[string]bool
	if err := json.Unmarshal(data, &m); err != nil {
		return
	}
	probeCache = m
	slog("probe cache loaded: %d entries from %s", len(m), path)
}

// SaveProbeCache 持久化缓存。
func SaveProbeCache() {
	probeMu.Lock()
	defer probeMu.Unlock()
	saveProbeCacheLocked()
}

func saveProbeCacheLocked() {
	if probePath == "" {
		return
	}
	data, err := json.Marshal(probeCache)
	if err != nil {
		return
	}
	if err := os.WriteFile(probePath, data, 0644); err != nil {
		slog("probe cache save failed: %v", err)
	}
}

// ProbeCacheLen 缓存条目数（诊断用）。
func ProbeCacheLen() int {
	probeMu.Lock()
	defer probeMu.Unlock()
	return len(probeCache)
}

// shouldForceCF 决策：域名是否强制走 CF。
// 1. 静态名单（x.com 全家桶）→ 强制
// 2. 云配置 force_cf 名单（远程可调，见 cloudconfig.go）→ 强制
// 3. 缓存记录 → 按记录
// 4. 无记录 → 触发后台探测，先用保守（不强改）
func shouldForceCF(name string) bool {
	n := strings.ToLower(name)
	n = strings.TrimSuffix(n, ".")

	// 静态名单（已实测 CF 有内容）
	if isForceCF(n) {
		return true
	}
	// 云配置名单（2026-08-15 远程可调，改服务器 JSON 即生效，零出包）
	if cloudForceCF(n) {
		return true
	}

	probeMu.Lock()
	if v, ok := probeCache[n]; ok {
		probeMu.Unlock()
		return v
	}
	// 无记录：触发后台探测（异步，不阻塞当前查询）
	if !probeProbe[n] {
		probeProbe[n] = true
		go probeDomain(n)
	}
	probeMu.Unlock()
	return false
}

// probeDomain 后台探测：连 CF 边缘 + ECH，TLS 证书验证。
// 成功（CF 有证书）= 可强改；失败 = 不可强改。结果写缓存并持久化。
// 2026-08-15 优化：先查 A 记录是否 CF（AS13335）—— 非 CF 域名
// （mozilla/Google/Apple 等）直接标记 NOT-forceable，不做 ECH 握手。
// 冷启动日志里 firefox.settings/accounts.google 等探测纯浪费 20s。
func probeDomain(name string) {
	defer func() {
		probeMu.Lock()
		delete(probeProbe, name)
		probeMu.Unlock()
	}()
	slog("probe: testing %s against CF edge...", name)

	// 快速判定：A 记录全部非 CF → 直接 NOT-forceable（不做 ECH 握手）
	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	r, err := queryUpstream(q)
	if err == nil && r != nil {
		var ips []string
		for _, rr := range r.Answer {
			if a, ok := rr.(*mdns.A); ok {
				ips = append(ips, a.A.String())
			}
		}
		if len(ips) > 0 && !cloudflare.AllAS13335(ips) {
			slog("probe: %s A=%v not CF (cname=), keep original -> NOT-forceable (fast)", name, ips)
			probeMu.Lock()
			probeCache[name] = false
			saveProbeCacheLocked()
			probeMu.Unlock()
			return
		}
	}

	d := tlsconn.New(8*time.Second, false, false)
	hintIPs := fetchDohEndpointIPv4s()
	// 强制连 CF 边缘（DoH 端点 IP，大陆可达）
	d.SetCustomIPs(strings.Join(hintIPs, ","))
	// 构造 dns.Result：ECH 配置从 cloudflare-ech.com 拉
	cfg := fetchCFPublicECH()
	if len(cfg) == 0 {
		slog("probe: %s no ECH config, mark NOT-forceable", name)
		probeMu.Lock()
		probeCache[name] = false
		saveProbeCacheLocked()
		probeMu.Unlock()
		return
	}
	res := &dns.Result{}
	res.ECH = &dns.ECHConfig{Config: cfg}
	res.OuterSNI = "cloudflare-ech.com"
	// DialECH 要求 IPs 非空；custom IPs 优先连接，这里放同批 CF 边缘兜底
	res.IPs = make([]net.IP, 0, len(hintIPs))
	for _, h := range hintIPs {
		if ip := net.ParseIP(h); ip != nil {
			res.IPs = append(res.IPs, ip)
		}
	}

	conn, err := d.DialECH(name, res)
	if err != nil {
		slog("probe: %s CF edge TLS FAILED: %v -> mark NOT-forceable", name, err)
		probeMu.Lock()
		probeCache[name] = false
		saveProbeCacheLocked()
		probeMu.Unlock()
		return
	}
	// 关键：ECH 握手验证的是外层 SNI（cloudflare-ech.com）的证书，
	// 必须再验证内层——服务器证书链应对应目标域名，才说明 CF 有内容。
	forceable := false
	if uc, ok := conn.(*utls.UConn); ok {
		state := uc.ConnectionState()
		if certs := state.PeerCertificates; len(certs) > 0 {
			pool := x509.NewCertPool()
			for _, c := range certs[1:] {
				pool.AddCert(c)
			}
			_, verr := certs[0].Verify(x509.VerifyOptions{
				DNSName:       strings.TrimSuffix(name, "."),
				Roots:         pool,
				Intermediates: pool,
			})
			if verr == nil {
				forceable = true
			} else {
				slog("probe: %s inner cert verify FAILED: %v", name, verr)
			}
		}
	}
	conn.Close()
	if forceable {
		slog("probe: %s CF edge TLS OK (inner cert valid) -> mark forceable ✓", name)
	} else {
		slog("probe: %s inner cert mismatch -> mark NOT-forceable", name)
	}
	probeMu.Lock()
	probeCache[name] = forceable
	saveProbeCacheLocked()
	probeMu.Unlock()
}
