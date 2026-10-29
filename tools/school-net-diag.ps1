#Requires -Version 5.1
<#
  school-net-diag.ps1   (v2)
  用途：在被限制的校园网机器上运行，判定封锁发生在哪一层
        （DNS 劫持 / IP 层丢包 / SNI-DPI 重置 / 网关HTTP拦截 / IPv6 放行），
        并给出对应方案编号 A/B/C/D/E。
  用法：powershell -NoProfile -ExecutionPolicy Bypass -File .\school-net-diag.ps1
  输出：屏幕 + 同目录 diag-report.txt
  说明：只做被动探测，不修改任何系统设置、不安装任何东西。
#>

param([string]$OutFile = (Join-Path $PSScriptRoot 'diag-report.txt'))

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$lines = New-Object System.Collections.Generic.List[string]

function Say([string]$s) { Write-Host $s; [void]$lines.Add($s) }

# 注意：PowerShell 5.1 里 curl 是 Invoke-WebRequest 的别名，会盖掉同名函数，
# 所以探测函数必须改名字，且调用 curl.exe 时要带 .exe。
function Probe([string[]]$curlArgs, [int]$timeout = 8) {
    $a = @('-s', '-o', 'NUL', '-w', '%{http_code}', '--max-time', "$timeout") + $curlArgs
    $out = & curl.exe @a 2>$null
    $code = $LASTEXITCODE
    return [pscustomobject]@{ Http = (($out | Out-String).Trim()); Exit = $code }
}

function Rate($r) {
    if ($null -eq $r) { return 'NO-RESULT' }
    switch ([int]$r.Exit) {
        0 { if ($r.Http -in @('200', '204', '301', '302')) { return 'OK' } else { return "OK(HTTP $($r.Http))" } }
        6 { return 'DNS-FAIL      -> 方案 A（DoH）' }
        7 { return 'REFUSED       -> 网关主动拒绝，方案 E' }
        28 { return 'TIMEOUT       -> IP/端口层被丢包，方案 D/E' }
        35 { return 'TLS-RESET     -> 握手被打断，典型 SNI/DPI 阻断，方案 B（首选）' }
        56 { return 'RECV-ERR      -> 连接被重置，SNI/DPI 阻断，方案 B（首选）' }
        60 { return 'CERT-ERR      -> 证书不受信，疑似网关中间人，方案 E' }
        default { return "EXIT $($r.Exit)   -> 需人工跑 curl -v 看细节" }
    }
}

function Get-DohA([string]$name) {
    foreach ($u in @(
            "https://dns.alidns.com/resolve?name=$name&type=A",
            "https://doh.pub/dns-query?name=$name&type=A")) {
        try {
            $r = Invoke-RestMethod -Uri $u -Headers @{ accept = 'application/dns-json' } -TimeoutSec 6
            $ips = @($r.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { $_.data })
            if ($ips.Count -gt 0) { return , $ips }
        } catch { }
    }
    return , @()
}

function Get-DohAAAA([string]$name) {
    try {
        $r = Invoke-RestMethod -Uri "https://dns.alidns.com/resolve?name=$name&type=AAAA" -TimeoutSec 6
        return , @($r.Answer | Where-Object { $_.type -eq 28 } | ForEach-Object { $_.data })
    } catch { return , @() }
}

Say ('=' * 78)
Say "校园网封锁层级诊断  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Say ('=' * 78)
Say ''

# ---------- 0. 环境 ----------
Say '## 0. 出口与环境'
try { Say ('  公网出口 IPv4: ' + (Invoke-RestMethod -Uri 'https://myip.ipip.net' -TimeoutSec 6)) }
catch { Say '  公网出口 IPv4: 获取失败' }
try { Say ('  IPv6 可用    : ' + (Invoke-RestMethod -Uri 'https://api6.ipify.org' -TimeoutSec 6)) }
catch { Say '  IPv6 可用    : 否（方案 C 不可行）' }
try {
    $ad = (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | Select-Object -First 1)
    Say ('  本机DNS      : ' + (($ad.ServerAddresses) -join ', '))
} catch { }
Say ''

# ---------- 1. 逐目标 ----------
$targets = @(
    @{ N = '抖音-网页';    H = 'www.douyin.com' },
    @{ N = '抖音-分享';    H = 'v.douyin.com' },
    @{ N = '抖音-API';     H = 'aweme.snssdk.com' },
    @{ N = '抖音-视频CDN';  H = 'v3-web.douyinvod.com' },
    @{ N = '抖音-图片CDN';  H = 'p3-sign.douyinpic.com' },
    @{ N = '淘宝-网页';    H = 'www.taobao.com' },
    @{ N = '淘宝-H5';      H = 'h5.m.taobao.com' },
    @{ N = '阿里-CDN';     H = 'gw.alicdn.com' },
    @{ N = '淘宝-图片CDN';  H = 'img.alicdn.com' },
    @{ N = '对照-百度';    H = 'www.baidu.com' }
)

Say '## 1. 逐目标五连测：系统DNS / DoH真值 / 带SNI / 无SNI / IPv6'
Say ''
$summary = @()

foreach ($t in $targets) {
    $h = $t.H
    Say "--- [$($t.N)] $h"

    $sys = @()
    try { $sys = @((Resolve-DnsName $h -Type A -QuickTimeout -ErrorAction Stop | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })) } catch { }
    Say ('   系统DNS : ' + $(if ($sys.Count) { $sys -join ', ' } else { '解析失败/超时' }))

    $real = Get-DohA $h
    Say ('   DoH真值 : ' + $(if ($real.Count) { ($real | Select-Object -First 6) -join ', ' } else { '查询失败' }))

    $dnsV = 'UNKNOWN'
    if ($sys.Count -eq 0) { $dnsV = 'DNS-失败' }
    elseif ($real.Count -eq 0) { $dnsV = 'DNS-无法比对' }
    elseif (@($sys | Where-Object { $real -contains $_ }).Count -gt 0) { $dnsV = 'DNS-一致' }
    else { $dnsV = 'DNS-污染' }
    Say "   DNS判定 : $dnsV"

    if ($real.Count -eq 0) { Say '   => 无法继续 IP 层测试'; Say ''; continue }
    $ip1 = $real[0]

    $c1 = Probe @("https://$h/")
    Say "   带SNI   : HTTP=$($c1.Http) exit=$($c1.Exit)  $(Rate $c1)"

    $c2 = Probe @('--resolve', "${h}:443:${ip1}", "https://$h/")
    Say "   IP+SNI  : HTTP=$($c2.Http) exit=$($c2.Exit)  $(Rate $c2)"

    $c3 = Probe @('-k', "https://$ip1/")
    Say "   无SNI   : HTTP=$($c3.Http) exit=$($c3.Exit)  $(Rate $c3)"

    $v6r = Get-DohAAAA $h
    $c4 = $null
    if ($v6r.Count -gt 0) {
        $c4 = Probe @('-6', "https://$h/")
        Say "   IPv6    : 有AAAA($($v6r[0])) HTTP=$($c4.Http) exit=$($c4.Exit)  $(Rate $c4)"
    }
    else {
        Say '   IPv6    : 无 AAAA 记录'
    }

    $v = 'UNKNOWN'
    if ($c1.Exit -eq 0) { $v = '可直接访问' }
    elseif ($c2.Exit -eq 0) { $v = '仅DNS层问题 -> 方案A' }
    elseif ($c3.Exit -eq 0 -and $c2.Exit -ne 0) { $v = 'SNI/DPI阻断 -> 方案B' }
    elseif ($c3.Exit -eq 28 -and $c2.Exit -eq 28) { $v = 'IP层封锁 -> 方案D/E' }
    elseif ($c4 -and $c4.Exit -eq 0) { $v = 'IPv4被封但IPv6通 -> 方案C' }
    elseif ($c2.Exit -eq 7 -or $c3.Exit -eq 7) { $v = '网关拒绝 -> 方案E' }
    Say "   >>> 结论: $v"
    Say ''

    $summary += [pscustomobject]@{
        目标  = $t.N
        域名  = $h
        DNS   = $dnsV
        SNI   = $(if ($null -ne $c1) { $c1.Exit } else { 'NA' })
        无SNI = $(if ($null -ne $c3) { $c3.Exit } else { 'NA' })
        IPv6  = $(if ($c4) { $c4.Exit } else { 'NA' })
        结论  = $v
    }
}

# ---------- 2. 汇总 ----------
Say ('=' * 78)
Say '## 2. 汇总表'
Say ('{0,-14} {1,-24} {2,-9} {3,-6} {4,-6} {5,-6} {6}' -f '目标', '域名', 'DNS', 'SNI', '无SNI', 'IPv6', '结论')
foreach ($s in $summary) {
    Say ('{0,-14} {1,-24} {2,-9} {3,-6} {4,-6} {5,-6} {6}' -f $s.目标, $s.域名, $s.DNS, $s.SNI, $s.无SNI, $s.IPv6, $s.结论)
}
Say ''

# ---------- 3. 路径 ----------
Say '## 3. 路径追踪（判断断在校园网关内还是上游）'
Say ((tracert -d -h 12 -w 800 www.douyin.com | Out-String).Trim())
Say ''

# ---------- 4. 拦截页/证书指纹 ----------
Say '## 4. 响应头与证书指纹（判断是否被网关劫持/中间人）'
foreach ($h in @('www.douyin.com', 'www.taobao.com', 'www.baidu.com')) {
    Say "  [$h]"
    $hd = (& curl.exe -k -s -I --max-time 6 "https://$h/" 2>$null | Out-String)
    if ($hd) { ($hd -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 5) | ForEach-Object { Say ('    ' + $_.TrimEnd()) } }
    else { Say '    无响应头' }
    $cert = (& curl.exe -k -s -o NUL -w '%{ssl_verify_result}' --max-time 6 "https://$h/" 2>$null | Out-String).Trim()
    Say ('    ssl_verify_result = ' + $cert + '   (0=证书链正常；非0=被替换/中间人)')
}
Say ''

Say '诊断完成。把『结论』一栏对照方案 A/B/C/D/E 执行。'
Say "报告已写入: $OutFile"
try { ($lines -join "`r`n") | Out-File -FilePath $OutFile -Encoding UTF8 } catch { Write-Host "写报告失败: $_" }
