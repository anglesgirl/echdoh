package cloudflare

// CF IP 三阶段优选（2026-08-15 用户方案，10s 内完成；与 CO3
// ech/echproxy/preferred.go 同源）：
//   1. 采样 50 个不同 /16 网段的 CF IP → 并发 TCP connect 延迟排序
//      （2s 预算）→ 取延迟最低 10 个
//   2. 绑定 speed.cloudflare.com 下载测速（8s 预算）→ 取吞吐最高 3 个
//   3. 结果缓存到 cachePath/ipscan.json（12h TTL）：下次启动直接复用；
//      连接全失败时清缓存重扫（dial 层触发）。

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// speed.cloudflare.com 下载测速端点（CF 官方，国内可达）
	speedTestURL = "https://speed.cloudflare.com/__down?bytes=200000"
	probePort    = "443"
	ipCacheTTL   = 12 * time.Hour
)

// --- 1. 采样 50 个不同网段 ------------------------------------------------

// SampleAcrossSubnets 从 AS13335 IPv4 段展开 /16 子网列表，随机取 n 个
// 不同子网，每个子网随机生成 1 个 IP。
func SampleAcrossSubnets(n int, rng *rand.Rand) []string {
	var subnets []*net.IPNet
	for _, network := range parsedCIDRs {
		ip := network.IP.To4()
		if ip == nil {
			continue // 只取 IPv4
		}
		ones, _ := network.Mask.Size()
		if ones > 16 {
			subnets = append(subnets, network)
			continue
		}
		base := network.IP.To4()
		num := 1 << (16 - ones)
		for i := 0; i < num; i++ {
			s := make(net.IP, 4)
			copy(s, base)
			s[2] |= byte(i)
			subnets = append(subnets, &net.IPNet{IP: s, Mask: net.CIDRMask(16, 32)})
		}
	}
	rng.Shuffle(len(subnets), func(i, j int) { subnets[i], subnets[j] = subnets[j], subnets[i] })
	if len(subnets) > n {
		subnets = subnets[:n]
	}
	var out []string
	for _, sn := range subnets {
		ip := randomIPInNet(sn, rng)
		if ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

func randomIPInNet(network *net.IPNet, rng *rand.Rand) net.IP {
	ip := network.IP.To4()
	bits := 32
	if ip == nil {
		ip = network.IP.To16()
		bits = 128
	}
	if ip == nil {
		return nil
	}
	ones, _ := network.Mask.Size()
	out := make(net.IP, len(ip))
	copy(out, ip)
	hostBits := bits - ones
	if hostBits > 16 {
		hostBits = 16
	}
	for i := 0; i < hostBits; i++ {
		byteIdx := (ones + i) / 8
		bitIdx := 7 - (ones+i)%8
		if rng.Intn(2) == 1 {
			out[byteIdx] |= 1 << bitIdx
		}
	}
	return out
}

// --- 2. TCP connect 延迟排序（2s 预算） -----------------------------------

// LatencySort 并发测 TCP connect 延迟，按 RTT 升序返回前 n 个。
func LatencySort(ips []string, n int) []string {
	type res struct {
		ip string
		ms int64
	}
	ch := make(chan res, len(ips))
	var wg sync.WaitGroup
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			start := time.Now()
			d := &net.Dialer{Timeout: 1 * time.Second}
			conn, err := d.Dial("tcp", net.JoinHostPort(ip, probePort))
			if err != nil {
				return
			}
			conn.Close()
			ch <- res{ip, time.Since(start).Milliseconds()}
		}(ip)
	}
	wg.Wait()
	close(ch)
	var list []res
	for r := range ch {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ms < list[j].ms })
	if len(list) > n {
		list = list[:n]
	}
	out := make([]string, len(list))
	for i, r := range list {
		out[i] = r.ip
	}
	return out
}

// --- 3. speed.cloudflare.com 下载测速（8s 预算） ---------------------------

func speedTestIP(ip string, timeout time.Duration) (int64, bool) {
	start := time.Now()
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(ip, probePort))
	if err != nil {
		return 0, false
	}
	tc := tls.Client(conn, &tls.Config{ServerName: "speed.cloudflare.com", MinVersion: tls.VersionTLS12})
	hctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		tc.Close()
		return 0, false
	}
	// ⚠️ 读超时保护：speed.cloudflare.com keep-alive 不主动关连接，
	// 响应体读完后 br.Read 等 EOF 会永久阻塞（hctx 只管握手不管读）。
	tc.SetReadDeadline(time.Now().Add(timeout))
	req, _ := http.NewRequestWithContext(hctx, "GET", speedTestURL, nil)
	req.Host = "speed.cloudflare.com"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/125.0.0.0 Mobile Safari/537.36")
	if err := req.Write(tc); err != nil {
		tc.Close()
		return 0, false
	}
	br := bufio.NewReader(tc)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(statusLine, "HTTP/1.1 200") && !strings.HasPrefix(statusLine, "HTTP/2 200") {
		tc.Close()
		return 0, false
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			tc.Close()
			return 0, false
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	readBytes := int64(0)
	buf := make([]byte, 32*1024)
	for {
		n, err := br.Read(buf)
		readBytes += int64(n)
		if err != nil {
			break
		}
		if time.Since(start) >= timeout {
			break
		}
	}
	tc.Close()
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 || readBytes <= 0 {
		return 0, false
	}
	return int64(float64(readBytes) / elapsed), true
}

// SpeedSort 并发测速 top 候选，按吞吐降序取前 n 个。
func SpeedSort(ips []string, n int, budget time.Duration) []string {
	if len(ips) == 0 {
		return nil
	}
	type res struct {
		ip  string
		bps int64
	}
	perTimeout := budget / time.Duration(len(ips))
	if perTimeout < time.Second {
		perTimeout = time.Second
	}
	if perTimeout > 4*time.Second {
		perTimeout = 4 * time.Second
	}
	ch := make(chan res, len(ips))
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			bps, ok := speedTestIP(ip, perTimeout)
			if ok {
				ch <- res{ip, bps}
			}
		}(ip)
	}
	wg.Wait()
	close(ch)
	var list []res
	for r := range ch {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].bps > list[j].bps })
	if len(list) > n {
		list = list[:n]
	}
	out := make([]string, len(list))
	for i, r := range list {
		out[i] = r.ip
	}
	return out
}

// --- 缓存（12h TTL，下次启动复用） ----------------------------------------

type ipCache struct {
	IPs []string `json:"ips"`
	TS  int64    `json:"ts"`
}

func ipCachePath(cachePath string) string {
	if cachePath == "" {
		return ""
	}
	return filepath.Join(cachePath, "ipscan.json")
}

// ReadIPCache 读缓存（TTL 内返回 IP，过期/损坏返回 nil）。
func ReadIPCache(cachePath string) []string {
	p := ipCachePath(cachePath)
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var c ipCache
	if json.Unmarshal(b, &c) != nil || len(c.IPs) == 0 {
		return nil
	}
	if time.Since(time.Unix(c.TS, 0)) > ipCacheTTL {
		return nil
	}
	return c.IPs
}

// WriteIPCache 写缓存。
func WriteIPCache(cachePath string, ips []string) {
	p := ipCachePath(cachePath)
	if p == "" || len(ips) == 0 {
		return
	}
	os.MkdirAll(filepath.Dir(p), 0o755)
	b, _ := json.Marshal(ipCache{IPs: ips, TS: time.Now().Unix()})
	os.WriteFile(p, b, 0o644)
}

// ClearIPCache 清缓存（连接失败重扫时调用）。
func ClearIPCache(cachePath string) {
	p := ipCachePath(cachePath)
	if p == "" {
		return
	}
	os.Remove(p)
}

// --- 主流程 ---------------------------------------------------------------

// OptimizeFastIPs 三阶段优选入口（同步，≤10s）：
//   有缓存(12h) → 直接返回；无缓存 → 采样50网段 + 2s延迟排序 top10
//   + 8s下载测速 top3 → 写缓存。
func OptimizeFastIPs(cachePath string) []string {
	if cached := ReadIPCache(cachePath); len(cached) > 0 {
		return cached
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	cands := SampleAcrossSubnets(50, rng)
	if len(cands) == 0 {
		return nil
	}
	top := LatencySort(cands, 10)
	if len(top) == 0 {
		return nil
	}
	fast := SpeedSort(top, 3, 8*time.Second)
	if len(fast) == 0 {
		return nil
	}
	WriteIPCache(cachePath, fast)
	return fast
}
