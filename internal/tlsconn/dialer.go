// Package tlsconn implements ECH TLS connection establishment.
//
// Improvements ported from production ECH proxy:
//   - ECH rejection retry_configs: uses server-provided retry config on rejection
//   - No-downgrade mode: protected hosts never fall back to plain TLS
//   - Android cert pool: loads system CA store for CGO-free binaries
//   - Custom IP support: operator-supplied edge IPs tried first
//   - Multi-candidate dialing: tries all resolved IPs before failing
package tlsconn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"crypto/tls"
	"github.com/anglesgirl/echdoh/internal/certutil"
	"github.com/anglesgirl/echdoh/internal/cloudflare"
	"github.com/anglesgirl/echdoh/internal/dns"
	utls "github.com/refraction-networking/utls"
)

// Dialer establishes ECH TLS connections.
type Dialer struct {
	timeout       time.Duration
	skipVerify    bool
	fallbackPlain bool // ECH failed → plain TLS (set false for protected hosts)
	customIPs     []string
	certPool      *utls.Config
	// onRetryConfig, when set, persists a server-provided retry_configs to the
	// disk cache so the next connection handshakes straight from cache.
	onRetryConfig func(host string, config []byte)
}

// SetRetryConfigSink registers a callback that receives server-provided
// retry_configs after a successful ECH rejection retry, so they can be cached.
func (d *Dialer) SetRetryConfigSink(fn func(host string, config []byte)) {
	d.onRetryConfig = fn
}

// New creates an ECH dialer.
func New(timeout time.Duration, skipVerify, fallbackPlain bool) *Dialer {
	d := &Dialer{
		timeout:       timeout,
		skipVerify:    skipVerify,
		fallbackPlain: fallbackPlain,
	}
	if pool := certutil.LoadSystemCertPool(); pool != nil {
		d.certPool = &utls.Config{RootCAs: pool, MinVersion: utls.VersionTLS12}
	}
	return d
}

// SetCustomIPs configures operator-supplied edge IPs to try before DNS.
// Only AS13335 (Cloudflare) IPs are accepted.
func (d *Dialer) SetCustomIPs(ipList string) {
	d.customIPs = cloudflare.FilterAS13335(cloudflare.ParseIPList(ipList))
}

// AppendCustomIPs adds more candidate edge IPs (already validated by caller)
// to the end of the custom list, deduplicating against existing entries.
func (d *Dialer) AppendCustomIPs(ips []string) {
	if len(ips) == 0 {
		return
	}
	seen := make(map[string]bool, len(d.customIPs)+len(ips))
	for _, ip := range d.customIPs {
		seen[ip] = true
	}
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] {
			continue
		}
		// 只接受 AS13335:ECH 配置只对 Cloudflare 边缘有效。
		if !cloudflare.IsAS13335(ip) {
			continue
		}
		seen[ip] = true
		d.customIPs = append(d.customIPs, ip)
	}
}

// PrependCustomIPs puts speed-scanned preferred IPs at the FRONT of the
// candidate list (they won the network speed test, so they're tried first).
// Existing custom IPs (remote config / DoH endpoint) are kept after them.
func (d *Dialer) PrependCustomIPs(ips []string) {
	if len(ips) == 0 {
		return
	}
	seen := make(map[string]bool, len(d.customIPs)+len(ips))
	var fresh []string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] || !cloudflare.IsAS13335(ip) {
			continue
		}
		seen[ip] = true
		fresh = append(fresh, ip)
	}
	for _, ip := range d.customIPs {
		if !seen[ip] {
			seen[ip] = true
			fresh = append(fresh, ip)
		}
	}
	d.customIPs = fresh
}

// DialECH establishes an ECH TLS connection to hostname using DNS results.
func (d *Dialer) DialECH(hostname string, result *dns.Result) (net.Conn, error) {
	if len(result.IPs) == 0 {
		return nil, fmt.Errorf("no IP for %s", hostname)
	}

	// Build candidate address list: custom IPs (operator-verified edge,
	// e.g. DoH endpoint IPs known to be reachable) first, then DoH-resolved
	// IPs. Custom-first matters on restricted networks: DoH-resolved edge
	// IPs of the target may be blocked (GFW), while the DoH endpoint's own
	// AS13335 IP is by definition reachable — trying it first avoids
	// multi-second timeouts on blocked candidates.
	port := "443"
	var candidates []string
	for _, ip := range d.customIPs {
		candidates = append(candidates, net.JoinHostPort(ip, port))
	}
	for _, ip := range result.IPs {
		candidates = append(candidates, net.JoinHostPort(ip.String(), port))
	}

	tlsConfig := &utls.Config{
		ServerName:         hostname,
		MinVersion:         utls.VersionTLS12,
		InsecureSkipVerify: d.skipVerify,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	if d.certPool != nil {
		tlsConfig.RootCAs = d.certPool.RootCAs
	}

	// Configure ECH if available.
	hasECH := result.ECH != nil && len(result.ECH.Config) > 0
	if hasECH {
		// ECH 只在 TLS 1.3 中定义，故 ECH 连接必须强制 1.3。
		tlsConfig.MinVersion = utls.VersionTLS13
		tlsConfig.EncryptedClientHelloConfigList = result.ECH.Config
		if result.OuterSNI != "" {
			outerName := strings.TrimSuffix(result.OuterSNI, ".")
			if outerName != "" {
				tlsConfig.ServerName = outerName
			}
		}
		echB64 := base64.StdEncoding.EncodeToString(result.ECH.Config)
		log.Printf("[tls] ECH for %s -> outer=%s ech=%s...(len=%d)",
			hostname, tlsConfig.ServerName, truncStr(echB64, 40), len(result.ECH.Config))
	} else {
		log.Printf("[tls] no ECHConfig for %s, plain TLS", hostname)
	}

	// Try each candidate address.
	var lastErr error
	for _, addr := range candidates {
		conn, err := d.dialTLS(addr, tlsConfig, hostname)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		log.Printf("[tls] handshake via %s failed: %v", addr, err)

		// ECH rejection: try server-provided retry_configs.
		var rej *utls.ECHRejectionError
		if hasECH && errors.As(err, &rej) && len(rej.RetryConfigList) > 0 {
			log.Printf("[tls] ECH rejected via %s; retrying with server retry_configs", addr)
			retryConfig := tlsConfig.Clone()
			retryConfig.EncryptedClientHelloConfigList = rej.RetryConfigList
			conn, retryErr := d.dialTLS(addr, retryConfig, hostname)
			if retryErr == nil {
				if tlsConn, ok := conn.(*utls.UConn); ok && tlsConn.ConnectionState().ECHAccepted {
					log.Printf("[tls] ECH accepted via %s (retry_configs)", addr)
				}
				// 缓存 server retry_configs,下次直接用它握手。
				if d.onRetryConfig != nil {
					d.onRetryConfig(hostname, rej.RetryConfigList)
				}
				return conn, nil
			}
			log.Printf("[tls] retry_configs also failed via %s: %v", addr, retryErr)
		}
	}

	// Fallback to plain TLS (only if allowed and ECH was attempted).
	if hasECH && d.fallbackPlain {
		log.Printf("[tls] all ECH attempts failed for %s, falling back to plain TLS", hostname)
		plainConfig := &utls.Config{
			ServerName: hostname,
			// plain TLS 兼容老 CDN（只支持 TLS 1.2，如内容页静态资源源站）。
			MinVersion:         utls.VersionTLS12,
			InsecureSkipVerify: d.skipVerify,
			NextProtos:         []string{"h2", "http/1.1"},
		}
		if d.certPool != nil {
			plainConfig.RootCAs = d.certPool.RootCAs
		}
		for _, addr := range candidates {
			conn, err := d.dialTLS(addr, plainConfig, hostname)
			if err == nil {
				log.Printf("[tls] plain TLS fallback succeeded via %s", addr)
				return conn, nil
			}
		}
	}

	if lastErr == nil {
		lastErr = errors.New("no candidates to dial")
	}
	return nil, fmt.Errorf("TLS handshake failed for %s after %d candidate(s): %w",
		hostname, len(candidates), lastErr)
}

func (d *Dialer) dialTLS(addr string, cfg *utls.Config, hostname string) (net.Conn, error) {
	// 先尝试 utls(Chrome 指纹,降低 CF challenge 概率)。
	conn, err := dialTLSUtls(d, addr, cfg, hostname)
	if err == nil {
		return conn, nil
	}
	// utls 握手失败(GFW 内实测 502)→ 自动降级 crypto/tls 重试同一地址。
	// Go 1.24+ 的 ECH outer SNI 用 public_name 伪装,GFW 放行;指纹是 Go
	// 的会触发 CF challenge,由验证窗口流程兜底。
	log.Printf("[tls] utls handshake via %s failed: %v; retrying with crypto/tls", addr, err)
	return dialTLSStd(d, addr, toStdTLSConfig(cfg), hostname)
}

// toStdTLSConfig converts a utls.Config to a stdlib tls.Config for the
// fallback handshake. ECH config is carried over unchanged.
func toStdTLSConfig(cfg *utls.Config) *tls.Config {
	return &tls.Config{
		ServerName:                     cfg.ServerName,
		MinVersion:                     cfg.MinVersion,
		InsecureSkipVerify:             cfg.InsecureSkipVerify,
		NextProtos:                     cfg.NextProtos,
		RootCAs:                        cfg.RootCAs,
		EncryptedClientHelloConfigList: cfg.EncryptedClientHelloConfigList,
	}
}

func dialTLSUtls(d *Dialer, addr string, cfg *utls.Config, hostname string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: d.timeout}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", addr, err)
	}

	// 用 utls 模拟浏览器 TLS 指纹(Chrome),避免 CF 依据 JA3/ClientHello
	// 指纹判定为自动化工具而触发 challenge。
	// ⚠️ 2026-08-13 实测: utls.UConn 不是 *tls.Conn,Go http.Transport 的
	// addTLS 类型断言读不到其 ConnectionState → ALPN=h2 不被感知 → 用
	// HTTP/1.1 解析服务器发来的 h2 帧 → "malformed HTTP response" 502。
	// 修复: utls 通道 ALPN 只 offer http/1.1(服务器选 h1,无乱码)。
	// 指纹的 ALPN 段微调,CF 主要看 JA3 结构,影响可忽略。
	tlsCfg := *cfg
	tlsCfg.NextProtos = []string{"http/1.1"}
	tlsConn := utls.UClient(rawConn, &tlsCfg, utls.HelloChrome_Auto)
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}

	state := tlsConn.ConnectionState()
	if cfg.EncryptedClientHelloConfigList != nil {
		if state.ECHAccepted {
			log.Printf("[tls] ECH ACCEPTED for %s via %s (TLS %s, ALPN %q, utls)",
				hostname, addr, tlsVersionName(state.Version), state.NegotiatedProtocol)
		} else {
			log.Printf("[tls] WARNING: ECH was NOT accepted by server for %s via %s", hostname, addr)
		}
	}
	return tlsConn, nil
}

func dialTLSStd(d *Dialer, addr string, cfg *tls.Config, hostname string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: d.timeout}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", addr, err)
	}

	tlsConn := tls.Client(rawConn, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}

	state := tlsConn.ConnectionState()
	if cfg.EncryptedClientHelloConfigList != nil {
		if state.ECHAccepted {
			log.Printf("[tls] ECH ACCEPTED for %s via %s (TLS %s, ALPN %q, crypto/tls)",
				hostname, addr, tlsVersionName(state.Version), state.NegotiatedProtocol)
		} else {
			log.Printf("[tls] WARNING: ECH was NOT accepted by server for %s via %s", hostname, addr)
		}
	}
	return tlsConn, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case utls.VersionTLS13:
		return "1.3"
	case utls.VersionTLS12:
		return "1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// DialerWithCache wraps Dialer with an ECH config cache for repeated lookups.
type DialerWithCache struct {
	*Dialer
	resolver *dns.Resolver
	echMu    sync.Mutex
	echCache map[string][]byte
}

// NewWithCache creates a dialer that caches ECH configs per host.
func NewWithCache(d *Dialer, resolver *dns.Resolver) *DialerWithCache {
	return &DialerWithCache{
		Dialer:   d,
		resolver: resolver,
		echCache: make(map[string][]byte),
	}
}

// DialContext implements the http.Transport DialTLSContext interface.
// It resolves the host via DoH, fetches ECH config, and establishes a TLS connection.
func (dc *DialerWithCache) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	result, err := dc.resolver.Lookup(host, true)
	if err != nil {
		return nil, fmt.Errorf("DoH lookup %s: %w", host, err)
	}

	dc.ensureECH(host, result)

	return dc.DialECH(host, result)
}

// ensureECH fills result.ECH via the full ECH config chain when the plain
// Lookup found none (target's own HTTPS record has no ech=). The chain is:
// disk cache → cloudflare-ech.com (Cloudflare's official ECH public key,
// valid for all AS13335-hosted zones) → target's own HTTPS ech=.
// CF-hosted zones that don't publish ech= themselves (e.g. hanime1.me)
// still get ECH through Cloudflare's official public key instead of
// silently downgrading to plain TLS and leaking SNI.
//
// ⚠️ Guard: the Cloudflare public key is only injected when the target
// resolves to at least one AS13335 (Cloudflare) address. Non-Cloudflare
// hosts (e.g. getchu.com behind Japanese servers that only speak TLS 1.2)
// must stay on the plain TLS route — ECH forces TLS 1.3, so injecting the
// CF key there breaks handshakes that would otherwise succeed.
func (dc *DialerWithCache) ensureECH(host string, result *dns.Result) {
	if result.ECH != nil && len(result.ECH.Config) > 0 {
		return
	}
	if !hasAS13335IP(result.IPs) {
		return
	}
	b, outer, err := dc.resolver.FetchECHConfig(host)
	if err != nil || len(b) == 0 {
		return
	}
	result.ECH = &dns.ECHConfig{Config: b}
	if outer != "" {
		result.OuterSNI = outer
	}
	log.Printf("[tls] ECH config for %s from fallback chain (outer=%s, len=%d)",
		host, outer, len(b))
}

// hasAS13335IP reports whether any of the resolved addresses belongs to
// Cloudflare AS13335. ECH via the Cloudflare public key only makes sense
// for such hosts.
func hasAS13335IP(ips []net.IP) bool {
	for _, ip := range ips {
		if cloudflare.IsAS13335(ip.String()) {
			return true
		}
	}
	return false
}

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
