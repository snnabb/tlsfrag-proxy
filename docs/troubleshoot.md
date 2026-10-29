# 排查手册

按顺序走，不要跳。

---

## 第 0 步：确认程序真的在跑

**托盘有没有图标？**

- 没有 → 进程没起来。多半是端口被占用，启动时会弹一个错误框然后退出。
  ```bat
  TlsFragProxy.exe --port 8898
  ```
- 有 → 看 `TlsFragProxy.log`

日志第一屏应该长这样：

```
17:03:23  ==== 启动 ====
17:03:23  载入策略 3 条
17:03:23  监听 127.0.0.1:8899  delay=800ms
17:03:23  系统代理写入回读: 开 -> 127.0.0.1:8899
17:03:23  启动完成  管理系统代理=True
```

**`系统代理写入回读` 这一行是本程序对自己行为的唯一可信描述。** 它从注册表读回来打印，不是打印「我打算设置什么」。

---

## 第 1 步：系统代理到底生效了没有

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' |
  Select-Object ProxyEnable, ProxyServer, ProxyOverride
```

期望：

```
ProxyEnable   : 1
ProxyServer   : 127.0.0.1:8899
ProxyOverride : localhost;127.*;10.*;...;<local>
```

三种异常：

| 现象 | 原因 | 处理 |
|---|---|---|
| `ProxyEnable : 0` | 没写进去，或写完被关了 | 托盘菜单点「系统代理」那一项手动切换 |
| `ProxyServer` 是 `127.0.0.1:7897` 之类 | **被 Clash / V2Ray 抢了** | 见第 2 步 |
| 读不到 / 报错 | 安全软件拦截注册表 | 改用 `--no-proxy`，见第 3 步 |

程序每 4 秒复查一次，被改动会在日志里留痕并弹气泡：

```
17:09:56  系统代理状态变化: 开 -> 127.0.0.1:7897
17:09:56  [!] 系统代理不是本程序的值，可能被其他代理软件或安全软件改掉了。当前: 开 -> 127.0.0.1:7897
```

---

## 第 2 步：和 Clash 类软件冲突

`7897` 是 Clash Verge / Mihomo Party 的默认混合端口。这类软件开启「系统代理」后会周期性或事件驱动地重写 `ProxyServer`，与本程序抢同一个注册表项。

**方案 A：让本程序独占**

1. Clash 里关掉「系统代理」开关（不必退出程序）
2. 重启 TlsFragProxy.exe

**方案 B：让 Clash 管分流，本程序只管分片（推荐）**

```bat
TlsFragProxy.exe --no-proxy
```

Clash 配置：

```yaml
proxies:
  - name: "tlsfrag"
    type: http
    server: 127.0.0.1
    port: 8899

rules:
  - DOMAIN-SUFFIX,douyin.com,tlsfrag
  - DOMAIN-SUFFIX,taobao.com,tlsfrag
  - MATCH,DIRECT
```

两边各司其职，互不干扰。

---

## 第 3 步：浏览器不读系统代理

即使注册表正确，浏览器仍可能不走管。检查：

- 地址栏输入 `chrome://net-internals/#proxy`，看里面识别的代理是什么
- 装了 SwitchyOmega 这类扩展时，情景模式必须选 **「系统代理」**；选「直接连接」会完全忽略注册表
- Chrome 在代理变更前就启动的情况下，偶尔不重新读取 → 重启浏览器

---

## 第 4 步：走代理了，但目标站点打不开

看日志。

### `[X ] host 全部 IP 不可达`

该站点在这条网络上确实不通（可能也是境外黑洞），与被封锁无关。

```powershell
# 确认一下
curl.exe -v --max-time 8 https://host
```

### `[x] 1.2.3.4:443 超时，换下一个 IP`

双 A 记录站点的正常过程。程序会自动换下一个，把成功的记进 `policy.txt`。看到这条不必担心，只要最终有响应即可。

### `[FRAG] host` 但页面白屏

延时可能不够。把 `--delay` 调到 1200 试试：

```bat
TlsFragProxy.exe --delay 1200
```

如果 1200 也不行，说明该站点走的不是重组超时型封锁，本方案无效。

### `[PASS] host` 但资源加载失败

自动探测可能把某个其实被封的域名误判成直连。手动改 `policy.txt`：

```
host.name    blocked    1.2.3.4
```

重启生效。

---

## 第 5 步：整体变慢

### 先区分是「慢」还是「卡」

- 慢：页面渐进加载，只是每步多几百毫秒 → 正常，分段有固定成本
- 卡：长时间白屏、转圈 → 有连接在等超时

### 卡的情况

日志里找 `[X ]`，每个都是 4 秒（`--connect-timeout`）。数量多的话说明该页面依赖大量境外资源：

```bat
TlsFragProxy.exe --connect-timeout 2000
```

### 慢的情况

1. 确认 `policy.txt` 里的 `direct` 条目够多（说明学习生效了）
2. 把 `--delay` 从 800 降到 600
3. 用 Clash 规则精确指定需要分片的域名，避免自动探测的开销

### 一个反直觉的点

延时降下去会引入偶发失败，而**一次失败触发的浏览器重试，比 800ms 本身更伤体验**——重试意味着再等一个 800ms 加一个 RTT，还会打乱资源加载顺序。所以 800 通常比 500 手感更好。

---

## 第 6 步：怎么彻底恢复原状

1. 右键托盘 → **退出**（会自动还原系统代理为你启动前的值）
2. 右键托盘 → 取消勾选「开机自动启动」
3. 删除整个文件夹

没有服务、没有驱动、没有其他注册表残留。

如果程序被强杀导致系统代理没还原，手动恢复：

```powershell
.\TlsFragProxy.exe --no-proxy   # 先启动一次让它接管
# 右键托盘 -> 退出
```

或者直接改注册表：

```powershell
$k='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Set-ItemProperty $k -Name ProxyEnable -Value 0 -Type DWord
```

---

## 附：判定「这条网络到底适不适合本方案」

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\sni_probe.ps1 -Target www.example.com -Scan
```

矩阵里出现 `P` → 可用。
矩阵全 `.` → 封锁不是重组超时型的，本项目无效，别浪费时间调参数。
