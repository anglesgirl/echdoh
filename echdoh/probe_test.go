package echdoh

import (
	"os"
	"testing"
	"time"
)

// 验证探测：CF 域名（iwara.tv）标记 true，非 CF（baidu）标记 false
func TestProbe(t *testing.T) {
	os.Remove("/tmp/probe-cache.json")
	// 测试环境：手动初始化 upstream（Start 正常流程会设置）
	upstream = []string{"https://pieqllv9i7.cloudflare-gateway.com/dns-query"}
	LoadProbeCache("/tmp/probe-cache.json")

	// 首次访问触发探测（异步），等待完成
	probeDomain("iwara.tv")
	probeDomain("www.baidu.com")
	// 等探测 goroutine 完成（每次探测最长 ~10s）
	for i := 0; i < 60; i++ {
		probeMu.Lock()
		done := len(probeProbe) == 0
		probeMu.Unlock()
		if done {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	probeMu.Lock()
	defer probeMu.Unlock()
	if v, ok := probeCache["iwara.tv"]; !ok || !v {
		t.Errorf("iwara.tv should be forceable=true, got %v ok=%v", v, ok)
	}
	if v, ok := probeCache["www.baidu.com"]; !ok || v {
		t.Errorf("www.baidu.com should be forceable=false, got %v ok=%v", v, ok)
	}
	t.Logf("probe cache: iwara.tv=%v www.baidu.com=%v", probeCache["iwara.tv"], probeCache["www.baidu.com"])
}
