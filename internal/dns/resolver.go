// Package dns implements DoH (DNS-over-HTTPS) queries and DNS caching.
//
// Improvements ported from production ECH proxy:
//   - Multi-endpoint DoH: comma-separated URLs, tries each until one succeeds
//   - Wire-format SVCB parsing (RFC 3597) in addition to textual ech= output
//   - File-based ECH config cache with 12h TTL for faster cold starts
//   - Stale cache fallback: serve expired entries when DoH is unreachable
package dns

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/anglesgirl/echdoh/internal/certutil"
)

// ECHConfig stores the raw ECHConfigList bytes.
type ECHConfig struct {
	Config []byte
}

// Result is a DNS lookup result.
type Result struct {
	IPs      []net.IP
	ECH      *ECHConfig
	OuterSNI string // HTTPS record's outer SNI (for ECH)
	ExpireAt time.Time
}

// Resolver performs DoH queries with TTL-based caching.
type Resolver struct {
	dohURLs   []string // comma-split list, tried in order
	timeout   time.Duration
	cacheTTL  time.Duration
	cachePath string // optional file path for ECH config persistence
	client    *http.Client

	// overrides: per-host fixed IP list from the operator (seed TXT
	// `override=` field). Hosts listed here bypass DoH resolution for
	// A/AAAA and always dial these IPs with plain TLS — used when a
	// specific edge IP is blocked on some carriers while another works
	// (e.g. getchu.com: 210.155.150.145 blocked on mobile, .166 fine).
	overrides map[string][]net.IP

	mu    sync.RWMutex
	cache map[string]*Result
}

// New creates a DoH resolver.
// dohURL may be a comma-separated list of endpoints; each is tried in order.
func New(dohURL string, timeout, cacheTTL time.Duration) *Resolver {
	return NewWithCache(dohURL, timeout, cacheTTL, "")
}

// NewWithCache creates a resolver that persists ECH configs to a file.
// When DoH is unreachable, the cached file is used instead.
func NewWithCache(dohURL string, timeout, cacheTTL time.Duration, cachePath string) *Resolver {
	urls := parseDoHList(dohURL)

	transport := &http.Transport{}
	if pool := certutil.LoadSystemCertPool(); pool != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	return &Resolver{
		dohURLs:   urls,
		timeout:   timeout,
		cacheTTL:  cacheTTL,
		cachePath: cachePath,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		overrides: make(map[string][]net.IP),
		cache:     make(map[string]*Result),
	}
}

// SetOverrides configures per-host fixed IP lists, e.g.
// "www.getchu.com=210.155.150.166" (multiple hosts: comma+equals are
// ambiguous with multi-IP, so each host is its own call, or use
// "host=ip1,ip2" per host). Hosts listed bypass DoH A/AAAA resolution
// and are dialed with plain TLS only. Clears the DNS cache so the new
// overrides apply immediately.
func (r *Resolver) SetOverrides(spec string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		r.mu.Lock()
		r.overrides = make(map[string][]net.IP)
		r.cache = make(map[string]*Result)
		r.mu.Unlock()
		return
	}
	parts := strings.SplitN(spec, "=", 2)
	if len(parts) != 2 {
		log.Printf("[dns] override spec ignored (want host=ip[,ip...]): %q", spec)
		return
	}
	host := strings.ToLower(strings.TrimSpace(parts[0]))
	var ips []net.IP
	for _, s := range strings.Split(parts[1], ",") {
		s = strings.TrimSpace(s)
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	if host == "" || len(ips) == 0 {
		log.Printf("[dns] override spec ignored (bad host/IP): %q", spec)
		return
	}
	r.mu.Lock()
	r.overrides[host] = ips
	r.cache = make(map[string]*Result) // 换配置后清缓存,避免脏结果
	r.mu.Unlock()
	log.Printf("[dns] override %s -> %v (plain TLS)", host, ips)
}

// Lookup resolves a hostname, returning cached results when available.
func (r *Resolver) Lookup(hostname string, preferIPv4 bool) (*Result, error) {
	r.mu.RLock()
	if cached, ok := r.cache[hostname]; ok && time.Now().Before(cached.ExpireAt) {
		r.mu.RUnlock()
		return cached, nil
	}
	// Per-host override: fixed IP list from the operator, no DoH A/AAAA,
	// no ECH (plain TLS only — the override IP may be a non-CF edge).
	if ips, ok := r.overrides[strings.ToLower(hostname)]; ok && len(ips) > 0 {
		r.mu.RUnlock()
		result := &Result{
			IPs:      ips,
			ExpireAt: time.Now().Add(r.cacheTTL),
		}
		r.mu.Lock()
		r.cache[hostname] = result
		r.mu.Unlock()
		log.Printf("[dns] override hit for %s -> %v (plain TLS)", hostname, ips)
		return result, nil
	}
	r.mu.RUnlock()

	result, err := r.dohLookup(hostname)
	if err != nil {
		// Stale cache fallback: serve expired entry rather than failing.
		r.mu.RLock()
		if stale, ok := r.cache[hostname]; ok && len(stale.IPs) > 0 {
			r.mu.RUnlock()
			log.Printf("[dns] DoH failed for %s, using stale cache: %v", hostname, err)
			return stale, nil
		}
		r.mu.RUnlock()
		return nil, err
	}

	if preferIPv4 {
		r.sortIPv4First(result.IPs)
	}

	result.ExpireAt = time.Now().Add(r.cacheTTL)
	r.mu.Lock()
	r.cache[hostname] = result
	r.mu.Unlock()

	return result, nil
}

// ClearCache clears the in-memory DNS cache.
func (r *Resolver) ClearCache() {
	r.mu.Lock()
	r.cache = make(map[string]*Result)
	r.mu.Unlock()
}

// DoHURLs returns the configured DoH endpoints.
func (r *Resolver) DoHURLs() []string {
	return r.dohURLs
}

// SetDoHURLs hot-updates the DoH endpoint list (from seed TXT config).
func (r *Resolver) SetDoHURLs(urls []string) {
	var cleaned []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u != "" {
			cleaned = append(cleaned, u)
		}
	}
	if len(cleaned) == 0 {
		return
	}
	r.mu.Lock()
	r.dohURLs = cleaned
	r.cache = make(map[string]*Result) // 换源后清缓存,避免脏结果
	r.mu.Unlock()
	log.Printf("[dns] DoH endpoints updated: %v", cleaned)
}

func (r *Resolver) sortIPv4First(ips []net.IP) {
	for i := 0; i < len(ips); i++ {
		if ips[i].To4() != nil {
			if i != 0 {
				ips[0], ips[i] = ips[i], ips[0]
			}
			break
		}
	}
}

// --- multi-endpoint DoH query ---

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func (r *Resolver) dohQuery(hostname, qtype string) (*dohResponse, error) {
	var lastErr error
	for _, base := range r.dohURLs {
		base = strings.TrimSpace(base)
		if base == "" {
			continue
		}

		u, err := url.Parse(base)
		if err != nil {
			lastErr = err
			continue
		}
		q := u.Query()
		q.Set("name", hostname)
		q.Set("type", qtype)
		u.RawQuery = q.Encode()

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := r.client.Do(req)
		if err != nil {
			lastErr = err
			log.Printf("[dns] DoH query via %s failed: %v", base, err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("DoH HTTP %d via %s", resp.StatusCode, base)
			continue
		}

		var dr dohResponse
		if err := json.Unmarshal(body, &dr); err != nil {
			lastErr = fmt.Errorf("JSON parse via %s: %w", base, err)
			continue
		}
		if dr.Status != 0 {
			lastErr = fmt.Errorf("DoH DNS status %d via %s", dr.Status, base)
			continue
		}
		return &dr, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no DoH endpoint configured")
	}
	return nil, lastErr
}

func (r *Resolver) dohLookup(hostname string) (*Result, error) {
	result := &Result{}

	type queryResult struct {
		ips       []net.IP
		ech       *ECHConfig
		outerName string
		err       error
	}

	ch := make(chan queryResult, 3)

	go func() {
		ips, err := r.queryType(hostname, "A")
		ch <- queryResult{ips: ips, err: err}
	}()
	go func() {
		ips, err := r.queryType(hostname, "AAAA")
		ch <- queryResult{ips: ips, err: err}
	}()
	go func() {
		ech, outerName, err := r.queryHTTPS(hostname)
		ch <- queryResult{ech: ech, outerName: outerName, err: err}
	}()

	var firstErr error
	for i := 0; i < 3; i++ {
		qr := <-ch
		if qr.err != nil {
			log.Printf("[dns] query error for %s: %v", hostname, qr.err)
			if firstErr == nil {
				firstErr = qr.err
			}
			continue
		}
		if qr.ips != nil {
			result.IPs = append(result.IPs, qr.ips...)
		}
		if qr.ech != nil {
			result.ECH = qr.ech
		}
		if qr.outerName != "" {
			result.OuterSNI = qr.outerName
		}
	}

	if len(result.IPs) == 0 {
		if firstErr == nil {
			firstErr = errors.New("no A/AAAA records returned")
		}
		return nil, firstErr
	}

	return result, nil
}

func (r *Resolver) queryType(hostname, qtype string) ([]net.IP, error) {
	dr, err := r.dohQuery(hostname, qtype)
	if err != nil {
		return nil, err
	}

	typeNum := 1 // A
	if qtype == "AAAA" {
		typeNum = 28
	}

	var ips []net.IP
	for _, ans := range dr.Answer {
		if ans.Type != typeNum {
			continue
		}
		if ip := net.ParseIP(ans.Data); ip != nil {
			if qtype == "A" && ip.To4() != nil {
				ips = append(ips, ip)
			} else if qtype == "AAAA" && ip.To4() == nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

// --- HTTPS (type 65) record parsing ---

// echParamRe matches "ech=<base64>" in textual SVCB output.
var echParamRe = regexp.MustCompile(`(?:^|\s)ech="?([A-Za-z0-9+/=]+)"?`)

func (r *Resolver) queryHTTPS(hostname string) (*ECHConfig, string, error) {
	dr, err := r.dohQuery(hostname, "HTTPS")
	if err != nil {
		return nil, "", err
	}

	for _, ans := range dr.Answer {
		if ans.Type != 65 {
			continue
		}
		data := ans.Data

		// Format 1: textual SVCB — "1 . ech=<base64> alpn=h2"
		if match := echParamRe.FindStringSubmatch(data); match != nil {
			value, err := base64.StdEncoding.DecodeString(match[1])
			if err != nil {
				return nil, "", fmt.Errorf("ECH base64 decode: %w", err)
			}
			outerName := extractOuterSNI(data)
			return &ECHConfig{Config: value}, outerName, nil
		}

		// Format 2: RFC 3597 wire format — "\\# <len> <hex>"
		if ech, outerName, err := parseSVCBWire(data); err == nil && ech != nil {
			return &ECHConfig{Config: ech}, outerName, nil
		}
	}
	return nil, "", nil
}

func extractOuterSNI(data string) string {
	parts := strings.Fields(data)
	if len(parts) < 2 {
		return ""
	}
	outerName := parts[1]
	if outerName == "." {
		return ""
	}
	return strings.TrimSuffix(outerName, ".")
}

// parseSVCBWire extracts the ech SvcParam (key 5) from RFC 3597 wire format.
func parseSVCBWire(data string) ([]byte, string, error) {
	if !strings.HasPrefix(data, `\# `) {
		return nil, "", fmt.Errorf("not RFC3597 wire format")
	}
	parts := strings.Fields(data)
	if len(parts) < 3 {
		return nil, "", fmt.Errorf("malformed RFC3597 wire format")
	}
	hexStr := strings.Join(parts[2:], "")
	wire, err := hex.DecodeString(hexStr)
	if err != nil || len(wire) < 3 {
		return nil, "", fmt.Errorf("invalid SVCB wire data")
	}

	pos := 2 // skip SvcPriority

	// Parse TargetName (DNS name format, null-terminated)
	outerName := ""
	for pos < len(wire) && wire[pos] != 0 {
		labelLen := int(wire[pos])
		pos++
		if pos+labelLen > len(wire) {
			return nil, "", fmt.Errorf("invalid SVCB target name")
		}
		label := string(wire[pos : pos+labelLen])
		if outerName == "" {
			outerName = label
		} else {
			outerName += "." + label
		}
		pos += labelLen
	}
	pos++ // skip null terminator

	// Parse SvcParams (key-length-value triples)
	for pos+4 <= len(wire) {
		key := int(binary.BigEndian.Uint16(wire[pos:]))
		valLen := int(binary.BigEndian.Uint16(wire[pos+2:]))
		pos += 4
		if pos+valLen > len(wire) {
			break
		}
		if key == 5 { // SvcParamKey 5 = ech
			return append([]byte(nil), wire[pos:pos+valLen]...), outerName, nil
		}
		pos += valLen
	}
	return nil, outerName, fmt.Errorf("no ECH SvcParam found")
}

// --- file-based ECH config cache ---

// ECH 公钥配置缓存 5 小时:公钥轮换频率远低于此,期间连接直接用缓存握手,
// 避免每次启动/换 host 都实时查 DoH。兜底配置(server retry_configs /
// cloudflare-ech.com / 目标自身 ech=)同样缓存,失败后降级普通 TLS。
const publicECHCacheTTL = 5 * time.Hour

type publicECHCache struct {
	Host      string `json:"host"`
	ConfigB64 string `json:"config_b64"`
	ExpiresAt int64  `json:"expires_at"`
}

func LoadECHCacheFile(path, host string) []byte {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var record publicECHCache
	if json.Unmarshal(data, &record) != nil {
		return nil
	}
	if !strings.EqualFold(record.Host, host) {
		return nil
	}
	if record.ExpiresAt <= time.Now().Unix() {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(record.ConfigB64)
	if err != nil || len(b) == 0 {
		return nil
	}
	return b
}

func StoreECHCacheFile(path, host string, config []byte) {
	if strings.TrimSpace(path) == "" || len(config) == 0 {
		return
	}
	record, err := json.Marshal(publicECHCache{
		Host:      strings.ToLower(host),
		ConfigB64: base64.StdEncoding.EncodeToString(config),
		ExpiresAt: time.Now().Add(publicECHCacheTTL).Unix(),
	})
	if err != nil {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".echconfig-")
	if err != nil {
		return
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(record); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Rename(name, path)
}

// cloudflareECHHost 是 Cloudflare 官方的 ECH 公钥发布点。它的 HTTPS 记录里
// 带 ech= 参数,代表 Cloudflare 边缘的当前 ECH 公钥,适用于所有 Cloudflare
// 托管的 AS13335 目标(archiveofourown.org 即其中之一)。
const cloudflareECHHost = "cloudflare-ech.com"

// builtinCFECHConfig 是 cloudflare-ech.com 当前 HTTPS 记录的 ech= 参数快照,
// 内置为最后兜底:部分区域(如福建)会封禁 cloudflare-ech.com 的 IP 或干扰
// DoH 查询,导致公共 ECH 公钥永远拉不到、缓存永远填充不了。内置一份后,
// 即使 DoH/cloudflare-ech.com 全挂,AS13335 主机仍能用这份公钥发起 ECH
// 握手;若公钥已轮换,服务器会返回 retry_configs,代码自动用新公钥重试并
// 更新缓存(见 dialer.go 的 ECHRejectionError 处理),所以内置值过期无害。
// 2026-08-13 抓取自 cloudflare-ech.com HTTPS 记录。
const builtinCFECHConfigB64 = "AEX+DQBBNAAgACCyup0GYiVj1Iph45mjgzNuuKu0qMra6LGPbZVfMTXgJwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="

// CacheECHConfig persists an ECHConfigList for a host to the disk cache.
// Exported so the dialer can cache server-provided retry_configs too.
func (r *Resolver) CacheECHConfig(host string, config []byte) {
	if r.cachePath != "" && len(config) > 0 {
		StoreECHCacheFile(r.cachePath, host, config)
	}
}

// FetchECHConfig returns the ECHConfigList for an AS13335 host, trying in order:
//  1. the local 5h disk cache (learned from a previous fetch or retry_configs)
//  2. cloudflare-ech.com's HTTPS ech= (Cloudflare's official ECH public key)
//  3. the target's own HTTPS ech= record
//
// The first successful source is persisted to the cache so subsequent
// connections handshake straight from cache without another DoH round-trip.
func (r *Resolver) FetchECHConfig(host string) ([]byte, string, error) {
	// 1. Cache first:握手用缓存配置,不发 DoH。
	if r.cachePath != "" {
		if cached := LoadECHCacheFile(r.cachePath, host); cached != nil {
			log.Printf("[dns] using file-cached ECH config for %s", host)
			return cached, "", nil
		}
	}

	// 2. Cloudflare 官方 ECH 公钥(适用所有 CF 站点)。
	if ech, outer, err := r.queryHTTPS(cloudflareECHHost); err == nil && ech != nil {
		r.CacheECHConfig(host, ech.Config)
		log.Printf("[dns] ECH config for %s from %s (outer=%s)", host, cloudflareECHHost, outer)
		return ech.Config, outer, nil
	}

	// 3. 目标自身 HTTPS 记录的 ech=。
	if ech, outerName, err := r.queryHTTPS(host); err == nil && ech != nil {
		r.CacheECHConfig(host, ech.Config)
		log.Printf("[dns] ECH config for %s from target HTTPS ech=", host)
		return ech.Config, outerName, nil
	}

	// 4. 内置 Cloudflare 公共公钥(最后兜底)。
	// 部分区域封禁 cloudflare-ech.com 的 IP / 干扰 DoH,导致上面 1-3 全失败。
	// 内置快照保证 AS13335 主机仍能发起 ECH 握手;公钥轮换由服务器
	// retry_configs 兜底(握手被拒时自动更新),无需网络拉取也能自愈。
	if b, err := base64.StdEncoding.DecodeString(builtinCFECHConfigB64); err == nil && len(b) > 0 {
		r.CacheECHConfig(host, b)
		log.Printf("[dns] ECH config for %s from built-in Cloudflare public key (fallback)", host)
		return b, cloudflareECHHost, nil
	}

	return nil, "", fmt.Errorf("no ECH config available for %s", host)
}

// FetchTxt looks up TXT records over DoH and returns them joined by newlines.
func (r *Resolver) FetchTxt(name string) (string, error) {
	dr, err := r.dohQuery(name, "TXT")
	if err != nil {
		return "", err
	}
	var lines []string
	quotedRe := regexp.MustCompile(`"([^"]*)"`)
	for _, a := range dr.Answer {
		if a.Type != 16 {
			continue
		}
		s := a.Data
		if m := quotedRe.FindAllStringSubmatch(s, -1); len(m) > 0 {
			var b strings.Builder
			for _, g := range m {
				b.WriteString(g[1])
			}
			s = b.String()
		}
		s = strings.TrimSpace(s)
		if s != "" {
			lines = append(lines, s)
		}
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("no TXT records found for %s", name)
	}
	return strings.Join(lines, "\n"), nil
}

func parseDoHList(s string) []string {
	var urls []string
	for _, u := range strings.Split(s, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			urls = append(urls, u)
		}
	}
	return urls
}
