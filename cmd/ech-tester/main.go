// ech-tester performs a no-downgrade ECH handshake and reports its real state.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/anglesgirl/echdoh/internal/dns"
	"github.com/anglesgirl/echdoh/internal/tlsconn"
	utls "github.com/refraction-networking/utls"
)

const defaultDoH = "https://tgxjjdszvu.cloudflare-gateway.com/dns-query"

func main() {
	host := flag.String("host", "cloudflare-ech.com", "target hostname (port is always 443)")
	doh := flag.String("doh", defaultDoH, "DNS-over-HTTPS endpoint")
	echB64 := flag.String("ech", "", "base64 ECHConfigList; empty fetches via DoH")
	ip := flag.String("ip", "", "optional IPv4 or IPv6 target address")
	timeout := flag.Duration("timeout", 12*time.Second, "per-address timeout")
	skipVerify := flag.Bool("skip-verify", false, "diagnostic only: skip certificate validation while still requiring ECH acceptance")
	flag.Parse()

	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(*host)), ".")
	if name == "" {
		fatalf("host must not be empty")
	}

	resolver := dns.New(*doh, *timeout, time.Minute)
	result, err := resolver.Lookup(name, true)
	if err != nil {
		fatalf("DoH lookup failed: %v", err)
	}
	if *ip != "" {
		parsed := net.ParseIP(*ip)
		if parsed == nil {
			fatalf("invalid -ip value %q", *ip)
		}
		result.IPs = []net.IP{parsed}
	}

	source := "target HTTPS record"
	if *echB64 != "" {
		config, decodeErr := base64.StdEncoding.DecodeString(*echB64)
		if decodeErr != nil || len(config) == 0 {
			fatalf("invalid -ech ECHConfigList: %v", decodeErr)
		}
		result.ECH = &dns.ECHConfig{Config: config}
		result.OuterSNI = ""
		source = "-ech argument"
	} else if result.ECH == nil || len(result.ECH.Config) == 0 {
		config, outer, fetchErr := resolver.FetchECHConfig(name)
		if fetchErr != nil || len(config) == 0 {
			fatalf("no ECHConfigList available: %v", fetchErr)
		}
		result.ECH = &dns.ECHConfig{Config: config}
		result.OuterSNI = outer
		source = "Cloudflare ECH fallback"
	}

	fmt.Printf("target: %s\nips: %s\nouter_sni: %s\nech_source: %s\nech_config_bytes: %d\n",
		name, joinIPs(result.IPs), result.OuterSNI, source, len(result.ECH.Config))

	// fallbackPlain=false is essential: successful plain TLS is a test failure.
	// skipVerify exists only to reveal ECH rejection diagnostics, never as success criteria.
	conn, err := tlsconn.New(*timeout, *skipVerify, false).DialECH(name, result)
	if err != nil {
		fatalf("ECH handshake failed: %v", err)
	}
	defer conn.Close()

	accepted, version, alpn, certName := connectionInfo(conn)
	fmt.Printf("tls_version: %s\nalpn: %s\npeer_certificate: %s\nech_accepted: %t\n",
		version, alpn, certName, accepted)
	if !accepted {
		fatalf("server completed TLS but did not accept ECH")
	}
	fmt.Println("result: ECH handshake and certificate validation succeeded")
}

func connectionInfo(conn net.Conn) (bool, string, string, string) {
	switch c := conn.(type) {
	case *tls.Conn:
		s := c.ConnectionState()
		return s.ECHAccepted, tlsVersion(s.Version), s.NegotiatedProtocol, certificateName(s.PeerCertificates)
	case *utls.UConn:
		s := c.ConnectionState()
		return s.ECHAccepted, tlsVersion(s.Version), s.NegotiatedProtocol, certificateName(s.PeerCertificates)
	default:
		fatalf("unexpected TLS connection type %T", conn)
	}
	return false, "", "", ""
}

func certificateName(certs []*x509.Certificate) string {
	if len(certs) == 0 {
		return "(none)"
	}
	if certs[0].Subject.CommonName != "" {
		return certs[0].Subject.CommonName
	}
	if len(certs[0].DNSNames) > 0 {
		return certs[0].DNSNames[0]
	}
	return "(unnamed)"
}

func joinIPs(ips []net.IP) string {
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ",")
}

func tlsVersion(version uint16) string {
	if version == tls.VersionTLS13 {
		return "TLS 1.3"
	}
	if version == tls.VersionTLS12 {
		return "TLS 1.2"
	}
	return fmt.Sprintf("0x%04x", version)
}

func fatalf(format string, args ...any) {
	log.Printf("result: FAILED - "+format, args...)
	os.Exit(1)
}