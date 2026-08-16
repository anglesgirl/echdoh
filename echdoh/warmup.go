// 预热（2026-08-16）：启动后后台解析常用域名，填充解析缓存 + ECH 探测缓存。
// 用户访问时命中缓存秒回，治"等半天"。域名 = override 名单 + x.com 全家桶。
package echdoh

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func warmUpCache() {
	// 等云配置先拉取（override 名单预热才有意义）
	time.Sleep(3 * time.Second)

	hosts := map[string]bool{
		"x.com": true, "www.x.com": true, "abs.twimg.com": true, "pbs.twimg.com": true,
		"video.twimg.com": true, "api.x.com": true, "help.x.com": true,
	}
	cloudMu.Lock()
	for h := range overrideMap {
		hosts[h] = true
	}
	cloudMu.Unlock()

	for h := range hosts {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS} {
			// 走完整处理链（强制改写/ECH 注入/探测），结果写解析缓存
			q := new(dns.Msg)
			q.SetQuestion(dns.Fqdn(h), qt)
			resp, err := queryUpstream(q)
			if err != nil || resp == nil {
				continue
			}
			resp.Id = q.Id
			processResponse(resp, h)
			if out, perr := resp.Pack(); perr == nil {
				respCachePut(respCacheKey(q.Question[0].Name, qt), out)
			}
		}
	}
	slog("warm-up done")
}

// processResponse 应用 override/forced/ECH 注入等处理链（与 handleDoH 同逻辑）。
func processResponse(resp *dns.Msg, name string) {
	q := resp.Question[0]
	// override 分支（与 handleDoH 同逻辑：A 返回指定 IP，HTTPS 注入 ech=+hint）
	if ip, ok := matchOverride(q.Name); ok {
		switch q.Qtype {
		case dns.TypeA:
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
			resp.Answer = ans
		case dns.TypeAAAA:
			resp.Answer = nil
		case dns.TypeHTTPS:
			injectECHWithHints(resp, q.Name, strings.Split(ip, ","))
		}
		return
	}
	// forced 名单
	if shouldForceCF(q.Name) {
		switch q.Qtype {
		case dns.TypeA:
			forceRewriteA(resp, q.Name)
		case dns.TypeAAAA:
			rewriteAAAAEmpty(resp, q.Name)
		case dns.TypeHTTPS:
			injectECHForced(resp, q.Name)
		}
		return
	}
	// 普通 CF 处理
	if q.Qtype == dns.TypeHTTPS {
		injectECH(resp, q.Name)
	}
	if q.Qtype == dns.TypeA {
		rewriteAIfCF(resp, q.Name)
	}
}
