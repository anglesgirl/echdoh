// Package certutil loads the system CA certificate store across platforms.
//
// - Android: CGO-free Go binaries don't inherit Android's trust store, so we
//   scan the standard Android certificate directories (DER + PEM).
// - Windows: Go's crypto/x509 automatically uses the Windows certificate store
//   when RootCAs is nil, so we return nil and let the standard library handle it.
// - Linux/macOS: Same — Go's SystemCertPool works natively, so we return nil.
package certutil

import (
	"crypto/x509"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	pool *x509.CertPool
	once sync.Once
)

// LoadSystemCertPool returns the platform-appropriate CA certificate pool.
//
// On Android, it scans the standard cert directories for DER and PEM files.
// On Windows/Linux/macOS, it returns nil — the Go standard library
// automatically uses the OS certificate store when RootCAs is nil.
//
// Callers should check the return value: nil means "use Go's default".
func LoadSystemCertPool() *x509.CertPool {
	once.Do(func() {
		switch runtime.GOOS {
		case "android":
			pool = loadAndroidCerts()
		default:
			// Windows, Linux, macOS: Go's crypto/x509 handles system
			// roots natively when RootCAs is nil. No manual loading needed.
			//
			// On Windows specifically, Go uses the Windows certificate
			// store via the bcrypt/winapi bridge. On Linux it reads
			// /etc/ssl/certs, and on macOS it uses the Keychain.
			pool = nil
			log.Printf("[certutil] using OS-native certificate store (%s)", runtime.GOOS)
		}
	})
	return pool
}

// LoadAndroidCertPool is retained for backward compatibility.
// New code should use LoadSystemCertPool instead.
func LoadAndroidCertPool() *x509.CertPool {
	return LoadSystemCertPool()
}

func loadAndroidCerts() *x509.CertPool {
	p := x509.NewCertPool()
	loaded := 0
	for _, dir := range []string{
		"/system/etc/security/cacerts",
		"/apex/com.android.conscrypt/cacerts",
		"/system/etc/security/cacerts_google",
		"/data/misc/user/0/cacerts-added",
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			// Android stores certs as hashed DER; try parsing as a
			// single certificate first, then fall back to PEM bundle.
			if cert, err := x509.ParseCertificate(data); err == nil {
				p.AddCert(cert)
				loaded++
			} else if p.AppendCertsFromPEM(data) {
				loaded++
			}
		}
	}
	if loaded > 0 {
		log.Printf("[certutil] loaded %d Android system certificates", loaded)
		return p
	}
	return nil
}
