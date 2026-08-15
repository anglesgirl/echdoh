package echdoh

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
)

// override 分支必须同时处理 HTTPS：注入 ech= + ipv4hint=override IP。
// 2026-08-15 实测：旧代码只处理 A/AAAA，Firefox 拿到 A=172.64.146.66 但
// HTTPS 无 ech= 或 hints 不一致 → 明文 SNI 直连 → 被墙 loadError 0x93。
func TestHandleDoHOverrideInjectsECH(t *testing.T) {
	if len(upstream) == 0 {
		upstream = []string{"https://pieqllv9i7.cloudflare-gateway.com/dns-query"}
	}
	SetOverride("override-ech-test.example=172.64.146.66")
	defer SetOverride("")

	srv := httptest.NewServer(http.HandlerFunc(handleDoH))
	defer srv.Close()

	for _, qtype := range []uint16{dns.TypeA, dns.TypeHTTPS, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion("override-ech-test.example.", qtype)
		wire, _ := m.Pack()
		resp, err := http.Post(srv.URL+"/dns-query", "application/dns-message", bytes.NewReader(wire))
		if err != nil {
			t.Fatalf("POST %s: %v", dns.TypeToString[qtype], err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if len(body) == 0 {
			t.Fatalf("%s: empty body", dns.TypeToString[qtype])
		}
		out := new(dns.Msg)
		if err := out.Unpack(body); err != nil {
			t.Fatalf("%s: unpack: %v", dns.TypeToString[qtype], err)
		}
		switch qtype {
		case dns.TypeA:
			found := false
			for _, rr := range out.Answer {
				if a, ok := rr.(*dns.A); ok && a.A.String() == "172.64.146.66" {
					found = true
				}
			}
			if !found {
				t.Errorf("A: override IP missing: %v", out.Answer)
			}
		case dns.TypeHTTPS:
			// 必须含 ech= 且 ipv4hint 指向 override IP
			hasECH, hintOK := false, false
			for _, rr := range out.Answer {
				for _, kv := range svcbValues(rr) {
					switch v := kv.(type) {
					case *dns.SVCBECHConfig:
						hasECH = len(v.ECH) > 0
					case *dns.SVCBIPv4Hint:
						for _, ip := range v.Hint {
							if ip.String() == "172.64.146.66" {
								hintOK = true
							}
						}
					}
				}
			}
			if !hasECH {
				t.Errorf("HTTPS: missing ech= (明文 SNI 会被墙)")
			}
			if !hintOK {
				t.Errorf("HTTPS: ipv4hint 不包含 override IP")
			}
		case dns.TypeAAAA:
			if len(out.Answer) != 0 {
				t.Errorf("AAAA: 应为空")
			}
		}
	}
}
