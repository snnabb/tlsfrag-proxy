# Changelog

## [0.4.0] - 2026-10-29

### Added
- 多 A 记录逐个回退，成功的 IP 记入策略文件下次优先
- 普通 HTTP 转发（forward proxy），此前只支持 CONNECT
- 系统代理状态写入后回读并记日志，托盘菜单可直接查看与切换
- 4 秒轮询检测系统代理是否被其他软件改写，被改时记日志并弹气泡
- `--connect-timeout` / `--probe-timeout` 可配置

### Fixed
- 探测超时被误判为「被封锁」，导致慢站点被永久打进分段模式
  （改为只有 `SocketError.ConnectionReset` / `ConnectionAborted` 才判定为封锁）
- `TcpClient.Connect` 无超时，境外黑洞 IP 会阻塞约 21 秒并占用线程
- 只取首个 IPv4 的问题（典型症状：Cloudflare 双 A 记录的站点一个 IP 被黑洞就永久打不开）

## [0.3.0] - 2026-10-29

### Added
- 自动探测模式：首次访问某域名先试直连，被 RST 才改分段，结论持久化到 `policy.txt`
- DNS 缓存（默认 300 秒）

### Changed
- 默认不再需要维护域名白名单

### Removed
- 对全部域名无条件分段的行为（改为 `-Only "*"` 显式开启）

## [0.2.0] - 2026-10-29

### Added
- SOCKS5 入站支持
- 白名单模式
- 运行日志

### Fixed
- SOCKS5 握手首字节被重复消费的问题

## [0.1.0] - 2026-10-29

### Added
- 初版：HTTP CONNECT 隧道 + 动态 SNI 偏移解析 + 分段延时
- 探针工具 `tools/sni_probe.ps1`，支持「切点 × 延时」二维矩阵扫描
- 诊断工具 `tools/school-net-diag.ps1`，五连测判定封锁层级
