// 云配置：从 doh.anglesgirl.eu.org 的 TXT 记录拉取强制名单 / IP 覆盖 /
// 优选 IP 池。2026-08-15 用户要求：改 IP 每次走 App 对话框或重新出包太
// 麻烦。配置写在 DNS TXT 里（和 ech-proxy 的种子协议同一套机制，
// AGENTS.md 1.3），改配置 = 改 DNS 记录，零出包零部署。
//
// TXT 字段（每个字段一条 TXT 记录，与种子 doh=/ip= 风格一致）：
//
//	overrides=x.com=172.64.146.66,104.18.41.190;www.x.com=172.66.0.227   IP 覆盖（分号分隔规则，IP 逗号分隔）
//	force=xxx.com,yyy.com                                                  强制 CF 名单（后缀匹配，*.yyy.com 支持）
//	pool=172.64.146.66,104.18.41.190                                      优选 IP 池（并入候选）
//
// 查询走 upstream DoH（queryUpstream），不做系统 DNS —— 与主站解析同源
// 防污染。定时刷新，失败保留旧配置（fail-safe）。
package echdoh

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CloudConfig 远程配置（TXT 解析结果）。
type CloudConfig struct {
	Overrides map[string]string `json:"overrides"`
	ForceCF   []string          `json:"force_cf"`
	Rewrite   map[string]string `json:"rewrite"`
	Pool      []string          `json:"pool"`
}

var (
	cloudMu      sync.Mutex
	cloudCfg     CloudConfig
	cloudRunning bool
	cloudExtra   []string // 远程 pool 并入的额外 IP
	cloudDomain  = "doh.anglesgirl.eu.org"
	cloudTTL     = 10 * time.Minute
)

// StartCloudConfig 启动云配置拉取：立即拉一次，之后每 cloudTTL 刷新。
// 任何失败只记日志不 panic，保持当前配置不变（fail-safe）。
func StartCloudConfig() {
	cloudMu.Lock()
	if cloudRunning {
		cloudMu.Unlock()
		return
	}
	cloudRunning = true
	cloudMu.Unlock()

	fetchCloudConfigTXT()
	go func() {
		for {
			time.Sleep(cloudTTL)
			fetchCloudConfigTXT()
		}
	}()
}

// StopCloudConfig 停止定时刷新（测试用）。
func StopCloudConfig() {
	cloudMu.Lock()
	cloudRunning = false
	cloudMu.Unlock()
}

// fetchCloudConfigTXT 查 doh.anglesgirl.eu.org 的 TXT 记录并应用配置。
func fetchCloudConfigTXT() {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(cloudDomain), dns.TypeTXT)
	resp, err := queryUpstream(q)
	if err != nil || resp == nil {
		slog("cloud config TXT query failed: %v", err)
		return
	}

	// 收集 TXT 字符串，解析 k=v 字段
	fields := map[string]string{}
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			for _, s := range t.Txt {
				if i := strings.Index(s, "="); i > 0 {
					k := strings.ToLower(strings.TrimSpace(s[:i]))
					v := strings.TrimSpace(s[i+1:])
					if k != "" && v != "" {
						fields[k] = v
					}
				}
			}
		}
	}
	if len(fields) == 0 {
		slog("cloud config: no TXT fields on %s", cloudDomain)
		return
	}

	cfg := CloudConfig{Overrides: map[string]string{}, Rewrite: map[string]string{}}

	// overrides=x.com=ip,ip;host=ip
	if v := fields["overrides"]; v != "" {
		for _, rule := range strings.Split(v, ";") {
			rule = strings.TrimSpace(rule)
			if rule == "" {
				continue
			}
			parts := strings.SplitN(rule, "=", 2)
			if len(parts) == 2 {
				host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parts[0]), "."))
				ips := strings.TrimSpace(parts[1])
				if host != "" && ips != "" {
					cfg.Overrides[host] = ips
				}
			}
		}
	}

	// force=host,*.suffix
	if v := fields["force"]; v != "" {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				cfg.ForceCF = append(cfg.ForceCF, h)
			}
		}
	}

	// rewrite=from=to;from2=to2（Kotlin 扩展执行，这里仅记录）
	if v := fields["rewrite"]; v != "" {
		for _, rule := range strings.Split(v, ";") {
			rule = strings.TrimSpace(rule)
			if rule == "" {
				continue
			}
			parts := strings.SplitN(rule, "=", 2)
			if len(parts) == 2 {
				from := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parts[0]), "."))
				to := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parts[1]), "."))
				if from != "" && to != "" {
					cfg.Rewrite[from] = to
				}
			}
		}
	}

	// pool=ip,ip
	if v := fields["pool"]; v != "" {
		for _, ip := range strings.Split(v, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				cfg.Pool = append(cfg.Pool, ip)
			}
		}
	}

	cloudMu.Lock()
	cloudCfg = cfg
	cloudExtra = cfg.Pool
	cloudMu.Unlock()

	// 应用 overrides（远程覆盖本地）
	if len(cfg.Overrides) > 0 {
		var b strings.Builder
		for host, ip := range cfg.Overrides {
			b.WriteString(host + "=" + ip + ",")
		}
		SetOverride(b.String())
		slog("cloud config: overrides applied (%d)", len(cfg.Overrides))
		respCacheClear() // override 变更 → 旧解析缓存失效
	}
	slog("cloud config: force=%v pool=%v rewrite=%v", cfg.ForceCF, cfg.Pool, cfg.Rewrite)
}

// cloudForceCF 检查远程 force 名单（后缀匹配，含通配 *. 前缀）。
func cloudForceCF(name string) bool {
	cloudMu.Lock()
	defer cloudMu.Unlock()
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, pat := range cloudCfg.ForceCF {
		p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pat), "."))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			if strings.HasSuffix(n, p[1:]) { // ".twimg.com" 后缀
				return true
			}
		} else if n == p {
			return true
		}
	}
	return false
}

// cloudPoolIPs 返回远程 pool 的 IP 列表（并入可达池候选）。
func cloudPoolIPs() []string {
	cloudMu.Lock()
	defer cloudMu.Unlock()
	out := make([]string, len(cloudExtra))
	copy(out, cloudExtra)
	return out
}
