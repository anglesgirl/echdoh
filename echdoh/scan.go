// CF 边缘 IP 随机扫描：启动时从 CF 公开 IP 段随机生成候选，
// 并发测试 TCP 443 连通性，可达 IP 进入轮换池。访问失败自动换下一个
// （dialer 多候选顺序尝试天然支持）。解决单一 IP 大陆可达性抖动。
package echdoh

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

var (
	reachableMu  sync.Mutex
	reachableIPs []string // 扫描到的可达 CF IP（启动时更新，查询时并入候选）
)

// CF 公开 IPv4 段（官方列表，2026 有效）
var cfCIDRs = []string{
	"104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13",
	"162.158.0.0/15", "108.162.192.0/18", "188.114.96.0/20",
	"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
}

// StartScanCFIPs 后台扫描 CF IP 段，找 TCP 443 可达的 IP 进轮换池。
// 在 Start 内自动调用；App 启动即扫，完成后查询自动用新池。
func StartScanCFIPs(count int) {
	go func() {
		ips := scanReachableCFIPs(count, 3*time.Second)
		reachableMu.Lock()
		reachableIPs = ips
		reachableMu.Unlock()
		slog("CF IP scan: %d reachable candidates (of %d)", len(ips), count)
	}()
}

// scanReachableCFIPs 随机生成 count 个 CF IP，并发 TCP 443 连通性测试。
func scanReachableCFIPs(count int, timeout time.Duration) []string {
	// 生成随机候选
	seen := map[string]bool{}
	var cands []string
	for len(cands) < count {
		ip := randomCFIP()
		if !seen[ip] {
			seen[ip] = true
			cands = append(cands, ip)
		}
	}
	// 并发测试
	var mu sync.Mutex
	var ok []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16) // 16 并发
	for _, ip := range cands {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				ok = append(ok, ip)
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	return ok
}

// randomCFIP 从 CF 段随机生成一个 IP。
func randomCFIP() string {
	// 预解析段（每次调用便宜，可缓存但无所谓）
	type seg struct {
		start uint32
		count uint32
	}
	var segs []seg
	for _, cidr := range cfCIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		start := ipToUint32(ipnet.IP)
		ones, bits := ipnet.Mask.Size()
		size := uint32(1) << (bits - ones)
		segs = append(segs, seg{start, size})
	}
	if len(segs) == 0 {
		return "162.159.36.5"
	}
	s := segs[rand.Intn(len(segs))]
	off := uint32(rand.Int63n(int64(s.count)))
	// 跳过 .0 和 .255（部分段网络/广播地址，443 测试会失败浪费一次）
	ip := s.start + off
	if ip&0xff == 0 {
		ip++
	} else if ip&0xff == 0xff {
		ip--
	}
	return uint32ToIP(ip)
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(v uint32) string {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
}

// reachableCFIPs 返回当前轮换池（可达 IP 列表）。
func reachableCFIPs() []string {
	reachableMu.Lock()
	defer reachableMu.Unlock()
	out := make([]string, len(reachableIPs))
	copy(out, reachableIPs)
	return out
}

// ReachableCFIPsForTest 导出给测试/App 查看当前轮换池。
func ReachableCFIPsForTest() string {
	ips := reachableCFIPs()
	out := ""
	for _, ip := range ips {
		out += ip + "\n"
	}
	return out
}
