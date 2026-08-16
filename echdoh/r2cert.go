// R2 证书 OTA（2026-08-16）：App 启动从 Cloudflare R2 私有桶拉取
// doh.anglesgirl.eu.org 的 LE 证书（续期后服务器自动同步），本地 DoH
// 永远用最新证书 —— 用户端零重装。
//
// 安全：R2 私有桶 + 最小权限 key（内置 APK）+ AES-256-GCM 加密
// （passphrase 内置 APK，双重保护；该域名只服务 127.0.0.1 本地 DoH，
// 泄露影响面≈0）。
//
// 服务器侧（acme reloadcmd）用同加密逻辑上传：r2cert-enc.go（本模块内）。
package echdoh

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ---- AES-256-GCM 加解密（密钥 = SHA-256(passphrase)）----

func aesKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	return h[:]
}

// EncryptCertPayload 加密 cert+key（\n===KEY===\n 分隔），返回 base64。
// 供服务器端上传使用（本包测试/工具）。
func EncryptCertPayload(certPEM, keyPEM, passphrase string) (string, error) {
	block, err := aes.NewCipher(aesKey(passphrase))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain := []byte(certPEM + "\n===KEY===\n" + keyPEM)
	nonce := make([]byte, gcm.NonceSize())
	sealed := gcm.Seal(nonce, nonce, plain, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func decryptCertPayload(b64, passphrase string) ([]byte, error) {
	sealed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey(passphrase))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("payload too short")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// ---- S3 SigV4 最小实现（仅 GET 一个对象，R2 专用）----

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sigv4Get(endpoint, accessKey, secretKey, bucket, objectKey string, t time.Time) ([]byte, error) {
	amzDate := t.UTC().Format("20060102T150405Z")
	dateStamp := t.UTC().Format("20060102")
	region, service := "auto", "s3"
	host := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	canonicalURI := "/" + bucket + "/" + objectKey
	canonicalQuery := ""
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		host, sha256Hex(nil), amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	payloadHash := sha256Hex(nil)
	canonicalRequest := strings.Join([]string{
		"GET", canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	req, err := http.NewRequest(http.MethodGet, endpoint+canonicalURI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, scope, signedHeaders, signature))
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("R2 HTTP %d: %s", resp.StatusCode, string(b))
	}
	return io.ReadAll(resp.Body)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ---- 导出：App 启动拉取证书 ----

// FetchCertFromR2 从 R2 拉取加密证书并解密。
// 返回格式："certPEM\n===KEY===\nkeyPEM"；失败返回 ""（App 用内置兜底）。
func FetchCertFromR2(endpoint, bucket, objectKey, accessKey, secretKey, passphrase string) string {
	data, err := sigv4Get(endpoint, accessKey, secretKey, bucket, objectKey, time.Now())
	if err != nil {
		slog("FetchCertFromR2 GET failed: %v", err)
		return ""
	}
	// R2 存的是 base64 文本（服务器加密后上传）
	plain, err := decryptCertPayload(strings.TrimSpace(string(data)), passphrase)
	if err != nil {
		slog("FetchCertFromR2 decrypt failed: %v", err)
		return ""
	}
	return string(plain)
}

// FetchCertFromR2WithMeta 兼容测试用（解析 SigV4 需要的时间戳等）。
// 供测试验证签名逻辑。
func sigv4GetForTest(endpoint, accessKey, secretKey, bucket, objectKey string) ([]byte, error) {
	return sigv4Get(endpoint, accessKey, secretKey, bucket, objectKey, time.Now())
}

// ---- R2 上传（崩溃日志自动上报用，2026-08-16）----

func sigv4Put(endpoint, accessKey, secretKey, bucket, objectKey string, body []byte, contentType string) error {
	t := time.Now().UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	region, service := "auto", "s3"
	host := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	canonicalURI := "/" + bucket + "/" + objectKey
	payloadHash := sha256Hex(body)
	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		contentType, host, payloadHash, amzDate)
	signedHeaders := "content-type;host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := strings.Join([]string{"PUT", canonicalURI, "", canonicalHeaders, signedHeaders, payloadHash}, "\n")
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonicalRequest))}, "\n")
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	req, err := http.NewRequest(http.MethodPut, endpoint+canonicalURI, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, scope, signedHeaders, signature))
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("R2 PUT HTTP %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// UploadToR2 上传内容到 R2 私有桶（崩溃日志自动上报）。成功返回 true。
func UploadToR2(endpoint, bucket, objectKey, accessKey, secretKey, contentType, content string) bool {
	if err := sigv4Put(endpoint, accessKey, secretKey, bucket, objectKey, []byte(content), contentType); err != nil {
		slog("UploadToR2 failed: %v", err)
		return false
	}
	return true
}

var _ = json.Marshal // 保持 import
var _ = bytes.MinRead
var _ = url.QueryEscape
