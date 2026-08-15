package echdoh

import (
	"testing"
	"time"
)

// 验证 CF IP 扫描：应扫出若干可达 IP
func TestScan(t *testing.T) {
	StartScanCFIPs(32)
	// 等待扫描完成（32 个候选 × 3s 超时 / 16 并发 ≈ 最多 6s）
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		reachableMu.Lock()
		n := len(reachableIPs)
		reachableMu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	reachableMu.Lock()
	n := len(reachableIPs)
	t.Logf("scan found %d reachable IPs: %v", n, reachableIPs[:min(n, 8)])
	reachableMu.Unlock()
	if n == 0 {
		t.Fatal("no reachable CF IP found — scan broken or network blocked")
	}
}
