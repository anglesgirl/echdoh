package echdoh

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
)

// 回归：forced-CF 分支必须写出响应体。
//
// 2026-08-15 根因：handleDoH 的 forced-CF 分支（x.com 全家桶）改写完 IP、
// 注入完 ech= 后直接 return，从未 Pack + Write —— 响应体 0 字节。
// Firefox TRR 解析失败，trr.mode=3 无 Do53 回退 → loadError code=37。
// 日志里的 "x.com A -> 6 answers (forced-CF)" 只是内存里的答案。
func TestHandleDoHWritesBodyForForcedCF(t *testing.T) {
	if len(upstream) == 0 {
		upstream = []string{"https://pieqllv9i7.cloudflare-gateway.com/dns-query"}
	}

	srv := httptest.NewServer(http.HandlerFunc(handleDoH))
	defer srv.Close()

	// x.com = forced-CF 名单内；A / AAAA / HTTPS 三种类型全覆盖，
	// 因为三者走 forced-CF 里不同的 case 分支。
	for _, tc := range []struct {
		qtype     uint16
		wantAnswr bool // 是否要求至少 1 条 answer
	}{
		{dns.TypeA, true},
		{dns.TypeAAAA, false}, // 强制 IPv4：AAAA 清空是预期行为
		{dns.TypeHTTPS, true},
	} {
		name := dns.TypeToString[tc.qtype]
		t.Run(name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion("x.com.", tc.qtype)
			wire, err := m.Pack()
			if err != nil {
				t.Fatal(err)
			}

			resp, err := http.Post(srv.URL+"/dns-query",
				"application/dns-message", bytes.NewReader(wire))
			if err != nil {
				t.Skipf("upstream unreachable: %v", err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d body=%q", resp.StatusCode, body)
			}
			// 核心断言：响应体非空。空体时客户端报
			// "overflow unpacking uint16"，Firefox 直接 loadError。
			if len(body) == 0 {
				t.Fatal("empty response body — forced-CF 分支没写响应（回归）")
			}
			out := new(dns.Msg)
			if err := out.Unpack(body); err != nil {
				t.Fatalf("unpack %d bytes: %v", len(body), err)
			}
			if out.Id != m.Id {
				t.Errorf("id mismatch: got %d want %d", out.Id, m.Id)
			}
			if tc.wantAnswr && len(out.Answer) == 0 {
				t.Errorf("%s: no answers — Firefox 会立即 loadError", name)
			}
			t.Logf("%s: %d bytes, %d answers", name, len(body), len(out.Answer))
		})
	}
}

// 手动 override 分支同样必须写响应体（同一类 bug 的另一个出口）。
func TestHandleDoHWritesBodyForOverride(t *testing.T) {
	if len(upstream) == 0 {
		upstream = []string{"https://pieqllv9i7.cloudflare-gateway.com/dns-query"}
	}
	SetOverride("override-test.example=1.2.3.4")
	defer SetOverride("")

	srv := httptest.NewServer(http.HandlerFunc(handleDoH))
	defer srv.Close()

	m := new(dns.Msg)
	m.SetQuestion("override-test.example.", dns.TypeA)
	wire, _ := m.Pack()
	resp, err := http.Post(srv.URL+"/dns-query",
		"application/dns-message", bytes.NewReader(wire))
	if err != nil {
		t.Skipf("upstream unreachable: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Fatal("empty response body for override branch")
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	found := false
	for _, rr := range out.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.String() == "1.2.3.4" {
			found = true
		}
	}
	if !found {
		t.Errorf("override IP not in answers: %v", out.Answer)
	}
}
