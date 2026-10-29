# TlsFragProxy v0.4.2

![TlsFragProxy icon](assets/TlsFragProxy.png)

**中文：** TlsFragProxy 是一个面向 Windows 的本地代理。它读取 TLS ClientHello，找到 SNI 域名后把握手切成两段，并在两段之间加入可配置的停顿，帮助绕过“TCP 能连通，但网关会根据 SNI 重置连接”的网络阻断。

**English:** TlsFragProxy is a small local proxy for Windows. It reads the TLS ClientHello, locates the SNI name, splits the handshake into two writes, and waits between them. This can help when a network resets connections after matching the SNI even though TCP connectivity itself works.

它只负责本地代理和 TLS 分片，不提供境外出口，也不会把无法建立 TCP 连接的目标 IP 变成可访问。它不是 VPN、远程代理或流量加密工具。

It only provides a local proxy and TLS fragmentation. It does not provide an overseas egress, turn an unreachable IP into a reachable one, or act as a VPN, remote proxy, or traffic encryption layer.

## 适用范围 / When it helps

**中文：** 它适合下面这种现象：

```text
TCP 建连成功
ClientHello 可以发出
带域名的 TLS 连接在等待响应时被 RST
把 ClientHello 分两段，并在中间等待后可以继续握手
```

**English:** It is designed for this pattern:

```text
TCP connection succeeds
The ClientHello is sent
The named TLS connection is reset while waiting for a response
The handshake succeeds after a delayed split
```

它无法解决 DNS 劫持、目标 IP 完全不可达、HTTP 中间人、证书替换或需要真实上游出口的场景。

It does not solve DNS hijacking, completely unreachable destination IPs, HTTP interception, certificate replacement, or cases that require a real upstream egress.

## 快速开始 / Quick start

### 使用发布版 exe / Run the release exe

1. **中文：** 下载 `TlsFragProxy.exe`，放到当前用户可写且不与其他账户共享的目录，例如 `C:\Tools\TlsFragProxy`。
   **English:** Download `TlsFragProxy.exe` and place it in a writable directory owned by the current user, such as `C:\Tools\TlsFragProxy`.
2. **中文：** 双击启动。程序会出现在系统托盘，并默认把 Windows 系统代理设置为 `127.0.0.1:8899`。
   **English:** Double-click it. The program appears in the system tray and sets the Windows system proxy to `127.0.0.1:8899` by default.
3. **中文：** 用浏览器访问目标网站。
   **English:** Browse to the target site.
4. **中文：** 右键托盘图标并选择“退出”。正常退出会恢复启动前的系统代理设置。
   **English:** Right-click the tray icon and choose **Exit**. A normal exit restores the system proxy captured at startup.

Windows 可能显示 SmartScreen 提示。程序目前没有数字签名，需要选择“更多信息 → 仍要运行”。

Windows may show a SmartScreen warning because the executable is not digitally signed. Choose **More info → Run anyway** if you trust the file.

程序会在 exe 同目录保存：

The executable stores these files beside itself:

```text
TlsFragProxy.log     运行日志 / runtime log
policy.txt           域名策略和最近成功的 IP / learned domain policy and last good IP
proxy-backup.txt     系统代理备份 / system proxy backup
```

如果程序被强制结束，下一次启动会检查系统代理是否仍指向自己，并尝试从 `proxy-backup.txt` 恢复。也可以手动执行：

If the process is force-terminated, the next launch checks for a leftover proxy pointing to itself and tries to restore `proxy-backup.txt`. You can also run:

```bat
TlsFragProxy.exe --restore
```

`--restore` 只恢复系统代理，不启动代理服务；没有备份时会关闭系统代理。

`--restore` only restores the system proxy and does not start the proxy. If no backup exists, it disables the system proxy.

## 自动探测 / Automatic probing

**中文：** 默认第一次访问某个域名时先直连探测：

**English:** On the first connection to a domain, the default mode probes a direct connection:

- 收到 TLS ServerHello（`0x16`）时记录为 `direct`，以后不增加分片延迟。
  A TLS ServerHello (`0x16`) is stored as `direct`, so later connections avoid the split delay.
- 被 RST 或 Aborted，或收到 TLS Alert（`0x15`）时记录为 `blocked`，以后使用分片。
  A reset, an aborted connection, or a TLS Alert (`0x15`) is stored as `blocked`, so later connections use fragmentation.
- 其他首字节只继续转发，不立即写入结论。
  Other first bytes are relayed without immediately storing a conclusion.

学习结果保存在 `policy.txt`，重启后仍然有效。托盘菜单里的“重置学习结果”会清空策略。

Results are stored in `policy.txt` and survive restarts. The tray menu item **Reset learned policy** clears them.

也可以在启动时清空：

You can also clear them at startup:

```bat
TlsFragProxy.exe --reset-policy
```

## 参数 / Options

| 参数 / Option | 默认值 / Default | 说明 / Description |
|---|---:|---|
| `--port` | `8899` | 本地监听端口 / local listening port |
| `--delay` | `800` | 两段 ClientHello 之间的等待毫秒数 / delay between ClientHello writes in milliseconds |
| `--connect-timeout` | `4000` | 单个目标 IP 的 TCP 建连超时 / TCP connect timeout per destination IP |
| `--probe-timeout` | `2500` | 自动探测等待目标首字节的时间 / time to wait for the first probe byte |
| `--no-proxy` | off | 不修改 Windows 系统代理 / do not change the Windows system proxy |
| `--reset-policy` | off | 启动时删除 `policy.txt` / delete `policy.txt` at startup |
| `--restore` | — | 只恢复系统代理 / restore the system proxy only |

示例 / Examples:

```bat
TlsFragProxy.exe --delay 1000
TlsFragProxy.exe --port 8898 --no-proxy
TlsFragProxy.exe --reset-policy
```

## 代理能力 / Proxy modes

**中文：** exe 只监听 `127.0.0.1`，支持：

**English:** The exe listens only on `127.0.0.1` and supports:

- HTTP CONNECT 隧道 / HTTP CONNECT tunnels;
- SOCKS5（IPv4、IPv6 和域名）/ SOCKS5 with IPv4, IPv6, and domain targets;
- 普通 HTTP forward proxy / ordinary HTTP forward proxy;
- 多个 A 记录逐个尝试，并记录最近一次成功的 IP / trying multiple A records and remembering the last successful IP.

只有 CONNECT 隧道中的 TLS ClientHello 会被分片。普通 HTTP 请求直接转发。

Only TLS ClientHellos inside CONNECT tunnels are fragmented. Ordinary HTTP requests are forwarded directly.

## 和 Clash / Mihomo 共存 / Using it with Clash or Mihomo

**中文：** 如果 Clash 或 Mihomo 管理系统代理，建议让它负责系统代理和分流，TlsFragProxy 只作为本地 HTTP 上游：

**English:** If Clash or Mihomo manages the system proxy, let it own system-proxy settings and routing, and run TlsFragProxy as a local HTTP upstream:

```bat
TlsFragProxy.exe --no-proxy
```

配置示例 / Example configuration:

```yaml
proxies:
  - name: tlsfrag
    type: http
    server: 127.0.0.1
    port: 8899

rules:
  - DOMAIN-SUFFIX,douyin.com,tlsfrag
  - DOMAIN-SUFFIX,iesdouyin.com,tlsfrag
  - DOMAIN-SUFFIX,snssdk.com,tlsfrag
  - DOMAIN-SUFFIX,douyinvod.com,tlsfrag
  - DOMAIN-SUFFIX,douyinpic.com,tlsfrag
  - DOMAIN-SUFFIX,taobao.com,tlsfrag
  - DOMAIN-SUFFIX,tmall.com,tlsfrag
  - DOMAIN-SUFFIX,alicdn.com,tlsfrag
  - MATCH,DIRECT
```

## 日志和排查 / Logs and troubleshooting

常见日志标记 / Common log markers:

```text
[PASS]  直连成功或继续直连 / direct or continued relay
[FRAG]  使用 TLS ClientHello 分片 / TLS ClientHello fragmentation
[PASS?] 未确认被重置，继续直连 / no confirmed reset, continue direct
[x]     当前 IP 失败，尝试下一个 / current IP failed, try the next one
[X ]    所有解析到的 IP 都失败 / all resolved IPs failed
[HTTP]  普通 HTTP 转发 / ordinary HTTP forwarding
```

排查顺序 / Suggested order:

1. **中文：** 先看 `[X ]`。如果目标 IP 完全不可达，需要真实上游代理。
   **English:** Check `[X ]` first. If every destination IP is unreachable, use a real upstream proxy.
2. **中文：** 看 `[FRAG]` 后是否仍失败。仍失败可能表示延迟不合适，或封锁方式不是 SNI 重组超时。
   **English:** If the connection still fails after `[FRAG]`, the delay may not fit the network, or the block may not be SNI reassembly based.
3. **中文：** 如果策略学错，删除 `policy.txt` 或运行 `--reset-policy`。
   **English:** If a policy was learned incorrectly, delete `policy.txt` or run `--reset-policy`.
4. **中文：** 如果系统代理显示其他端口，说明 Clash、浏览器扩展或安全软件接管了系统代理。
   **English:** If the system proxy shows another port, Clash, a browser extension, or security software has taken it over.

## 安全边界和隐私 / Security and privacy

- **中文：** 程序只监听 `127.0.0.1`，不会主动监听局域网或公网地址。
  **English:** The program listens only on `127.0.0.1` and does not listen on the LAN or the public network.
- **中文：** 本地端口没有账号认证；本机其他程序可以使用这个 HTTP/SOCKS5 代理。不要把端口映射到局域网或公网。
  **English:** The local port has no authentication. Other programs on the same computer can use the HTTP/SOCKS5 proxy. Do not expose or forward the port.
- **中文：** exe 不上传请求内容，也不保存 TLS 明文；日志主要记录域名、目标 IP、状态和错误类型。
  **English:** The exe does not upload request bodies or store TLS plaintext. Logs mainly contain domains, destination IPs, states, and error types.
- **中文：** 建议把 exe 放在当前用户独占且可写的目录，不要放在所有账户都可写的共享目录。
  **English:** Keep the exe in a writable directory owned by the current user, rather than a directory writable by every account.
- **中文：** 诊断脚本会访问公共 DoH 和公网 IP 查询服务；运行敏感域名诊断前请确认接受这种外部查询。
  **English:** The diagnostic scripts query public DoH and public-IP services. Check the privacy implications before running them for sensitive domains.

## 构建 / Build

Windows 自带的 .NET Framework C# 编译器即可构建，不需要 Visual Studio：

The .NET Framework C# compiler included with Windows is sufficient; Visual Studio is not required:

```bat
build.bat
```

构建脚本会把 `assets\TlsFragProxy.ico` 嵌入 exe，托盘也会读取 exe 自带图标。

The build script embeds `assets\TlsFragProxy.ico` into the exe, and the tray uses the same associated icon.

项目使用 .NET Framework 4.x、Windows Forms、注册表和 TCP 套接字，没有第三方运行时依赖。

The project uses .NET Framework 4.x, Windows Forms, the Windows registry, and TCP sockets. It has no third-party runtime dependency.

## 项目结构 / Project layout

```text
.
├── src\TlsFragProxy.cs        exe 主程序 / exe source
├── assets\TlsFragProxy.svg    图标源文件 / icon source
├── assets\TlsFragProxy.ico    Windows 多尺寸图标 / Windows icon
├── assets\TlsFragProxy.png    README 预览图 / README preview
├── tools\sni_probe.ps1        SNI 分片探针 / SNI probe
├── tools\school-net-diag.ps1  网络诊断工具 / network diagnostics
├── docs\how-it-works.md       原理文档 / technical notes
├── docs\troubleshoot.md       排查手册 / troubleshooting guide
├── build.bat                  构建脚本 / build script
└── README.md
```

## 限制 / Limitations

- **中文：** 分片只能绕过特定类型的 SNI/DPI 阻断；它不是 VPN 或境外代理出口。
  **English:** Fragmentation only helps with specific SNI/DPI blocks; it is not a VPN or overseas proxy.
- **中文：** 第一次访问新域名需要自动探测，可能比后续连接慢。
  **English:** The first connection to a new domain may be slower because it is probed.
- **中文：** 多个 IP 都不可达时，程序只能失败并返回 502。
  **English:** If all destination IPs are unreachable, the proxy can only fail with HTTP 502.
- **中文：** 过低的 `--delay` 可能落回网关的重组窗口；默认值为 800 ms。
  **English:** A low `--delay` may fall back inside the gateway's reassembly window; the default is 800 ms.

## License

MIT
