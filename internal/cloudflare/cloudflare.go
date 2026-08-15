// Package cloudflare provides AS13335 IP range validation.
//
// Only targets that resolve entirely to Cloudflare AS13335 addresses are
// eligible for ECH. Unknown addresses are treated as non-AS13335 and stay
// on the regular TLS route, preventing accidental ECH application to
// non-Cloudflare hosts.
package cloudflare

import (
	"net"
	"strings"
)

// AS13335 CIDR ranges (IPv4 + IPv6).
// Source: https://www.cloudflare.com/ips/
var as13335CIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

var parsedCIDRs []*net.IPNet

func init() {
	for _, cidr := range as13335CIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedCIDRs = append(parsedCIDRs, network)
		}
	}
}

// IsAS13335 returns true when the IP belongs to a Cloudflare AS13335 CIDR.
func IsAS13335(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, network := range parsedCIDRs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// AllAS13335 returns true only when every IP in the list is AS13335.
// An empty list returns false.
func AllAS13335(ips []string) bool {
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !IsAS13335(ip) {
			return false
		}
	}
	return true
}

// FilterAS13335 returns only the AS13335 addresses from the input list.
func FilterAS13335(ips []string) []string {
	var out []string
	for _, ip := range ips {
		if IsAS13335(ip) {
			out = append(out, ip)
		}
	}
	return out
}

// ParseIPList splits a comma/space separated string into valid IP literals.
func ParseIPList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == ';'
	}) {
		f = strings.TrimSpace(f)
		if net.ParseIP(f) != nil {
			out = append(out, f)
		}
	}
	return out
}
