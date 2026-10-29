# TlsFragProxy

一个只做一件事的本地代理：**把 TLS ClientHello 切成两段、中间停顿一下再发**，让做 TCP 流重组的 DPI 设备拼不出完整的 SNI，从而绕过基于域名黑名单的 HTTPS 阻断。

> A minimal local proxy that defeats SNI-based DPI by splitting the TLS ClientHello and inserting a delay between the two halves. Written for a campus network that reassembles TCP before matching the SNI field — a case where `--frag-by-sni`, `--disorder` and similar tools do **not** work, because they cannot introduce a delay.

Windows · .NET Framework 4.x · 单文件 22 KB · 无外部依赖

---

## 目录

- [它解决什么问题](#它解决什么问题)
- [为什么现有的工具不行](#为什么现有的工具不行)
- [快速开始](#快速开始)
- [工作模式](#工作模式)
- [参数](#参数)
- [和 Clash / V2Ray 共存](#和-clash--v2ray-共存)
- [常见问题](#常见问题)
- [自行构建](#自行构建)
- [目录结构](#目录结构)

---

## 它解决什么问题

某些网络的出口网关会对 TLS 握手里的 **SNI 字段**做黑名单匹配，命中就回 RST：

```
不带 SNI  →  TCP 握手成功，TLS 握手成功，服务器正常返回 HTTP 403
带 SNI    →  TCP 握手成功，ClientHello 发完，等响应时被 RST（curl exit 35）
用真实 IP 直连、只改 SNI →  同样被 RST
```

最后一条排除了 DNS 因素 —— 封锁点就在 SNI 字符串上。

问题在于，这类设备**不是只看第一个包**。把 ClientHello 拆成两个 TCP 段发出去，它会先把两段重组、解析出完整域名、然后再 RST。所以单纯的分段无效。

真正有效的做法是**在两次发送之间插入一段停顿**，让它的重组缓冲区先超时。

---

## 为什么现有的工具不行

| 工具 / 参数 | 切点正确 | 能控延时 | 结果 |
|---|---|---|---|
| GoodbyeDPI `--frag-by-sni` | ✅ | ❌ 无延时参数 | 落在 30ms 档，失败 |
| GoodbyeDPI `--disorder` | ✅ | ❌ 0 延时乱序 | 两段几乎同时到达，仍被重组 |
| zapret `--dpi-desync=split2` | ✅ | ❌ | 同上 |
| GreenTunnel `--fragment-delay` | ⚠️ 固定字节等分 | ✅ | 可用，但默认参数全错，且不保证切在域名内部 |

实测矩阵（同一网关、同一目标）：

```
delay\pos |  84  85  86  87  88  89  90  91  92  93  94  95  96  97  98  99
---------------------------------------------------------------------------
       30 |   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .
      400 |   .   P   P   P   P   .   P   P   P   P   P   P   P   .   P   ?
      800 |   P   P   P   P   P   P   P   P   P   P   P   P   P   P   P   ?
     1200 |   P   .   P   P   P   P   P   P   P   P   P   P   P   P   P   ?

P = 握手成功     . = 发完被 RST     ? = 其他
```

两个结论：

1. **30ms 行全灭** → 延时是必要条件，位置换了 16 个也没用。
2. **位置 99 全灭**（域名是 85~98）→ 两段里任何一段都不能包含完整域名。

所以有效条件是：**「切在域名内部」 × 「延时 > 网关重组缓冲超时」**，两个缺一不可。

本项目把这两件事都做对了：切点由 ClientHello 结构动态解析得出，延时可选。

---

## 快速开始

### 方式一：直接跑 exe（推荐）

1. 下载 `TlsFragProxy.exe`
2. 双击
3. 托盘出现图标，系统代理自动设为 `127.0.0.1:8899`
4. 直接用浏览器

退出：右键托盘 → 退出（会自动把系统代理还原成你原来的设置）。

> 首次运行 Windows 可能弹「Windows 已保护你的电脑」，点 **更多信息 → 仍要运行**。程序没有数字签名。

### 方式二：不需要编译，用 PowerShell 版

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\src\TlsFragProxy.ps1 -Delay 800 -Verbose
```

然后手动把浏览器代理设成 `127.0.0.1:8899`。

---

## 工作模式

### 自动探测（默认，推荐）

首次访问某个域名时先按**直连**试一次：

- 服务器正常回应 → 记为 `direct`，以后一直直连，**零延时**
- 被 RST → 记为 `blocked`，以后自动走分段（+800ms）

结论保存在 `policy.txt`，重启不丢。

这样做的原因是：按域名后缀猜白名单一定会误伤。一个淘宝页面能触发十几条分段请求，但其中很多子域其实没被封，白白多付 800ms。

### 固定白名单

```powershell
.\TlsFragProxy.ps1 -Only "douyin.com,taobao.com" -NoProbe
```

给了 `-Only` 就关闭探测，只对命中的域名分段。`-Only "*"` 表示全部分段。

### 手动干预

直接编辑 `policy.txt`（Tab 分隔）：

```
host                    state      ip
www.douyin.com          blocked    124.238.251.98
img.alicdn.com          direct     111.47.237.52
```

改完重启程序生效。

---

## 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--port` | 8899 | 本地监听端口 |
| `--delay` | 800 | 分段延时（毫秒）。低于 400 会不稳 |
| `--connect-timeout` | 4000 | 单 IP 建连超时，多 A 记录会逐个回退 |
| `--probe-timeout` | 2500 | 首次探测等待服务器首字节的时间 |
| `--no-proxy` | 关 | 不接管系统代理（自己用扩展或 Clash 管） |
| `--reset-policy` | 关 | 启动时清空学习结果 |

---

## 和 Clash / V2Ray 共存

这类软件会周期性重写 `HKCU\...\Internet Settings\ProxyServer`，和本程序抢同一个注册表项。直接同时开会出现「设置完立刻被改回去」。

**推荐做法：让 Clash 管分流，本程序只管分片。**

1. 本程序带 `--no-proxy` 启动，不碰系统代理
2. Clash 配置里把本程序加成上游：

```yaml
proxies:
  - name: "tlsfrag"
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

Clash 收到命中规则的请求后，会把 CONNECT 转发过来，本程序做完 TLS 分片再发出去。两边互不干扰。

---

## 常见问题

### 打开后系统代理没生效，还得手动设

托盘菜单里有一项直接显示真实状态：

```
系统代理: 开 -> 127.0.0.1:8899      ← 正常
系统代理: 开 -> 127.0.0.1:7897      ← 被别的软件抢了
系统代理: 关                        ← 没写进去
```

看 `TlsFragProxy.log` 里这一行：

```
系统代理写入回读: 开 -> 127.0.0.1:8899
```

- 显示正常但浏览器不走 → 检查浏览器扩展（SwitchyOmega 设成「直接连接」会忽略系统代理），或重启浏览器
- 显示被改成 `7897` 之类 → 被 Clash 抢了，见上一节
- 显示「无法读取注册表」 → 安全软件拦截，改用 `--no-proxy`

### 某些网站开了代理反而打不开

典型是双 A 记录的站点：一个 IP 被网络黑洞、另一个正常。浏览器会自动换，但只取首个 IP 的实现会卡死。本程序会**逐个尝试所有 A 记录**并把成功的那个记进 `policy.txt`。

如果仍然打不开，看日志里的 `[X ]`：

```
[X ] example.com 全部 IP 不可达
```

说明该站点在这条网络上确实不通，与被封锁无关。

### 部分站点没有变快

自动探测需要一轮学习。每个新域名第一次访问会多一次探测往返，之后走缓存。刷两遍就稳定了。

### 延时到底该设多少

800ms 是实测最优值。400ms 在阈值边缘，会出现偶发失败——而一次失败触发的浏览器重试比 800ms 本身更伤体验。

---

## 自行构建

不需要装 Visual Studio，用 Windows 自带的 C# 编译器：

```bat
build.bat
```

或者手动：

```bat
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe ^
  /target:winexe /platform:anycpu /optimize+ ^
  /r:System.dll /r:System.Core.dll ^
  /r:System.Windows.Forms.dll /r:System.Drawing.dll ^
  /out:TlsFragProxy.exe src\TlsFragProxy.cs
```

产物约 22 KB，不依赖任何运行库安装包（.NET Framework 4.x 是 Windows 10/11 自带组件）。

---

## 目录结构

```
.
├── src/
│   ├── TlsFragProxy.cs      主程序（C#，托盘 + 代理引擎，单文件）
│   └── TlsFragProxy.ps1     PowerShell 版，免编译
├── tools/
│   ├── sni_probe.ps1        SNI 分片探针：扫描「切点 × 延时」矩阵，判断本网络是否可用本方案
│   └── school-net-diag.ps1  网络诊断：逐目标判定封锁发生在 DNS / IP / SNI / 网关 HTTP 哪一层
├── docs/
│   ├── how-it-works.md      原理、实测数据、方法论
│   └── troubleshoot.md      排查手册
├── build.bat
└── README.md
```

**建议先跑 `tools\sni_probe.ps1 -Scan`** —— 如果矩阵里没有任何 `P`，说明这条网络的封锁不是重组超时型的，本方案不适用，别浪费时间。

---

## 使用范围

本项目用于诊断和访问自有网络环境下的正常业务站点。请自行确认所在网络的使用条款，以及在当地法律框架内使用。

---

## License

MIT
