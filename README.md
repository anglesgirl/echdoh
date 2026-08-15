# echdoh — 独立 DoH 服务模块

从 ech-proxy-go 抽出的独立 Go module：本地 DoH 服务（强注 CF 公共 ECH + 强改 A/HTTPS 记录 + fail-closed），供 GeckoView 浏览器（echbrowser / Iceraven）作为 TRR 上游使用。

## 功能
- RFC 8484 DoH 服务（监听 127.0.0.1:8443，需域名证书）
- 强制改写名单（x.com 全家桶）：注入 CF 公共 ECH 配置（71B ech=）+ 改写 A 记录到 ECH 可用 CF IP
- fail-closed：ECH 探测全失败的域名返回空 A（不暴露 SNI）
- 探测结果落盘缓存（echtest-cache.json：true 24h / false 1h，key=域名|IP）
- TXT 云配置（doh.anglesgirl.eu.org）：overrides / force / pool / rewrite
- 手动 IP 覆盖（域名=IP，多行）

## 构建
```bash
go build ./...
gomobile bind -javapkg com.anglesgirl.echdoh -target=android -androidapi 27 -o echdoh.aar ./echdoh
```

## Kotlin 集成
```kotlin
Echdoh.start("127.0.0.1:8443", certPem, keyPem, "https://pieqllv9i7.cloudflare-gateway.com/dns-query,https://162.159.36.5/dns-query")
Echdoh.setOverride("x.com=172.64.146.66")
Echdoh.loadEchTestCache(".../echtest-cache.json")
```
