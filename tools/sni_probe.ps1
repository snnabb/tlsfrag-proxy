#Requires -Version 5.1
<#
  sni_probe.ps1  v4  —— 纯 Windows 自带 PowerShell，零依赖
  在 v3 基础上新增「参数扫描」：自动遍历 [SNI 内部切分位置 × 分段间隔] 二维矩阵，
  找出稳定可用的组合并复测确认。

  v4 新增参数：
    -Scan                 跑二维扫描矩阵
    -Positions "85,86,88" 指定切分位置（默认 = SNI 域名在 ClientHello 中的所有字节位置）
    -Delays    "30,400,800,1200"  指定分段间隔毫秒（默认四档）
    -Repeat N             对通过的定义复测 N 次，判断稳定性

  典型用法：
    # 1) 复测上一轮那个通过组合，看是不是偶然
    .\sni_probe.ps1 -Target www.douyin.com -Splits "88" -DelayMs 800 -Repeat 5

    # 2) 全矩阵扫描，找出最稳的组合
    .\sni_probe.ps1 -Target www.douyin.com -Scan

    # 3) 指定 IP 避开解析问题
    .\sni_probe.ps1 -Target www.douyin.com -Ip 124.232.144.219 -Scan
#>

param(
    [Parameter(Mandatory = $true)][string]$Target,
    [string]$Ip,
    [string]$Sni,
    [string]$Splits,
    [int]$Timeout = 6,
    [int]$DelayMs = 30,
    [switch]$Scan,
    [string]$Positions,
    [string]$Delays,
    [int]$Repeat = 1
)

$ErrorActionPreference = 'Stop'

# ================= 字节工具（不能叫 Cat：PowerShell 5.1 的 cat 是 Get-Content 别名） =================
function BE16([int]$v) { [byte[]]@((($v -shr 8) -band 0xFF), ($v -band 0xFF)) }
function BE24([int]$v) { [byte[]]@((($v -shr 16) -band 0xFF), (($v -shr 8) -band 0xFF), ($v -band 0xFF)) }

function JoinBytes {
    param([object[]]$Parts)
    $ms = New-Object System.IO.MemoryStream
    foreach ($p in $Parts) {
        if ($null -eq $p) { continue }
        $b = [byte[]]$p
        $ms.Write($b, 0, $b.Length)
    }
    return $ms.ToArray()
}

function Find-Bytes([byte[]]$Haystack, [byte[]]$Needle) {
    $lim = $Haystack.Length - $Needle.Length
    for ($i = 0; $i -le $lim; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Haystack[$i + $j] -ne $Needle[$j]) { $ok = $false; break }
        }
        if ($ok) { return $i }
    }
    return -1
}

function New-ClientHello([string]$sni) {
    $rnd = New-Object byte[] 32
    (New-Object System.Random([Environment]::TickCount)).NextBytes($rnd)
    $nameBytes = [Text.Encoding]::ASCII.GetBytes($sni)

    $sniList = JoinBytes @([byte[]]@(0x00), (BE16 $nameBytes.Length), $nameBytes)
    $sniData = JoinBytes @((BE16 $sniList.Length), $sniList)
    $extSni = JoinBytes @((BE16 0x0000), (BE16 $sniData.Length), $sniData)

    $groups = JoinBytes @((BE16 0x001d), (BE16 0x0017), (BE16 0x0018))
    $grpData = JoinBytes @((BE16 $groups.Length), $groups)
    $extGrp = JoinBytes @((BE16 0x000a), (BE16 $grpData.Length), $grpData)

    $ecData = JoinBytes @([byte[]]@(0x01, 0x00))
    $extEc = JoinBytes @((BE16 0x000b), (BE16 $ecData.Length), $ecData)

    $sig = JoinBytes @((BE16 0x0403), (BE16 0x0804), (BE16 0x0401), (BE16 0x0503),
        (BE16 0x0805), (BE16 0x0501), (BE16 0x0806), (BE16 0x0601))
    $sigData = JoinBytes @((BE16 $sig.Length), $sig)
    $extSig = JoinBytes @((BE16 0x000d), (BE16 $sigData.Length), $sigData)

    $extRen = JoinBytes @((BE16 0xff01), (BE16 1), [byte[]]@(0x00))

    $exts = JoinBytes @($extSni, $extGrp, $extEc, $extSig, $extRen)
    $extBlock = JoinBytes @((BE16 $exts.Length), $exts)

    $ciphers = JoinBytes @((BE16 0x1301), (BE16 0x1302), (BE16 0x1303), (BE16 0xc02b),
        (BE16 0xc02f), (BE16 0xc02c), (BE16 0xc030), (BE16 0xcca9),
        (BE16 0xcca8), (BE16 0x009c), (BE16 0x009d), (BE16 0x002f),
        (BE16 0x0035))
    $cipherBlock = JoinBytes @((BE16 $ciphers.Length), $ciphers)

    $body = JoinBytes @(
        (BE16 0x0303),
        $rnd,
        [byte[]]@(0x00),
        $cipherBlock,
        [byte[]]@(0x01, 0x00),
        $extBlock
    )

    $hs = JoinBytes @([byte[]]@(0x01), (BE24 $body.Length), $body)
    return (JoinBytes @([byte[]]@(0x16, 0x03, 0x01), (BE16 $hs.Length), $hs))
}

function Test-One {
    param([string]$ip, [byte[]]$payload, [int[]]$splits, [int]$delayMs, [int]$timeout)
    $stage = 'CONNECT'
    $cli = New-Object Net.Sockets.TcpClient
    try {
        $iar = $cli.BeginConnect($ip, 443, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($timeout * 1000)) {
            return 'BLOCKED@CONNECT  (TCP 超时，IP 层被丢包)'
        }
        $cli.EndConnect($iar)
        try { $cli.NoDelay = $true } catch { }

        $s = $cli.GetStream()
        $s.ReadTimeout = $timeout * 1000
        $s.WriteTimeout = $timeout * 1000

        $stage = 'WRITE'
        if ($splits.Count -eq 0) {
            $s.Write($payload, 0, $payload.Length); $s.Flush()
        }
        else {
            $pos = 0
            foreach ($n in $splits) {
                if ($pos -ge $payload.Length) { break }
                $len = [Math]::Min($n, $payload.Length - $pos)
                $s.Write($payload, $pos, $len); $s.Flush()
                $pos += $len
                Start-Sleep -Milliseconds $delayMs
            }
            if ($pos -lt $payload.Length) {
                $s.Write($payload, $pos, $payload.Length - $pos); $s.Flush()
            }
        }

        $stage = 'READ'
        $buf = New-Object byte[] 16
        $r = $s.Read($buf, 0, 16)
        if ($r -le 0) { return 'BLOCKED@READ  (连接被关闭，无任何响应)' }

        $hex = (($buf[0..($r - 1)] | ForEach-Object { $_.ToString('X2') }) -join ' ')
        if ($buf[0] -eq 0x16) { return "PASS      (ServerHello: $hex)" }
        if ($buf[0] -eq 0x15) { return "PASS      (TLS Alert，SNI 已被服务端处理: $hex)" }
        return "UNKNOWN   (首字节 0x$($buf[0].ToString('X2')): $hex)"
    }
    catch {
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
        $msg = ($msg -split "`r?`n")[0]
        return "BLOCKED@$stage  ($msg)"
    }
    finally {
        try { $cli.Close() } catch { }
    }
}

function Resolve-Real {
    param([string]$name)
    foreach ($u in @(
            "https://dns.alidns.com/resolve?name=$name&type=A",
            "https://doh.pub/dns-query?name=$name&type=A")) {
        $raw = $null
        try { $raw = Invoke-RestMethod -Uri $u -Headers @{ accept = 'application/dns-json' } -TimeoutSec 6 }
        catch { Write-Host "    [DoH] 请求失败: $($_.Exception.Message)" -ForegroundColor DarkYellow; continue }
        if ($null -eq $raw) { Write-Host '    [DoH] 空响应，跳过' -ForegroundColor DarkYellow; continue }

        $cand = @()
        try { $cand = @($raw.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { [string]$_.data }) } catch { }

        $good = @()
        foreach ($c in $cand) {
            if ($c -match '^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$') { $good += $c }
            else { Write-Host "    [DoH] 丢弃非法结果: '$c'" -ForegroundColor DarkYellow }
        }
        if ($good.Count -gt 0) { return $good }
        Write-Host '    [DoH] 无有效 A 记录，换下一个端点' -ForegroundColor DarkYellow
    }
    return @()
}

# ================= 主流程 =================
$sniName = if ($Sni) { $Sni } else { $Target }

Write-Host ''
Write-Host '=== SNI 分片探针 v4 (PowerShell, 零依赖) ===' -ForegroundColor Cyan
Write-Host "目标域名 : $Target"
if ($Sni) { Write-Host "SNI 值   : $sniName   (与目标域名解耦)" -ForegroundColor Magenta }

$ips = @()
if ($Ip) { $ips = @($Ip); Write-Host "目标 IP   : $Ip   (手动指定)" }
else {
    Write-Host '  解析中...'
    $ips = @(Resolve-Real $Target)
    if (-not $ips.Count) {
        try {
            $ips = @([Net.Dns]::GetHostAddresses($Target) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                ForEach-Object { $_.ToString() })
            if ($ips.Count) { Write-Host "    [系统DNS] 兜底解析: $($ips -join ', ')" -ForegroundColor DarkYellow }
        }
        catch { }
    }
    if (-not $ips.Count) { Write-Host '解析失败 —— 用 -Ip 手动指定' -ForegroundColor Red; exit 2 }
    Write-Host "目标 IP   : $($ips[0])   (候选 $($ips.Count) 个)"
}

$ip = $ips[0]
$ch = New-ClientHello $sniName
$nameBytes = [Text.Encoding]::ASCII.GetBytes($sniName)
$sniOffset = Find-Bytes $ch $nameBytes
$midSplit = if ($sniOffset -ge 0 -and ($sniOffset + 3) -lt $ch.Length) { $sniOffset + 3 } else { 88 }
Write-Host "ClientHello: $($ch.Length) 字节"
Write-Host "SNI 偏移  : $sniOffset ~ $($sniOffset + $nameBytes.Length - 1)  (域名中段切点 = $midSplit)"
Write-Host ('-' * 70)

# ---------- 模式 A：二维扫描 ----------
if ($Scan) {
    if ($Positions) { $posList = @($Positions.Split(',') | Where-Object { $_.Trim() } | ForEach-Object { [int]$_.Trim() }) }
    else {
        $lo = [Math]::Max(1, $sniOffset - 1)
        $hi = [Math]::Min($ch.Length - 1, $sniOffset + $nameBytes.Length)
        $posList = @($lo..$hi)
    }
    if ($Delays) { $dlyList = @($Delays.Split(',') | Where-Object { $_.Trim() } | ForEach-Object { [int]$_.Trim() }) }
    else { $dlyList = @(30, 400, 800, 1200) }

    Write-Host "扫描矩阵: $($posList.Count) 个切点 x $($dlyList.Count) 档间隔 = $($posList.Count * $dlyList.Count) 次" -ForegroundColor Cyan
    Write-Host ''
    $hdr = 'delay\pos |'
    foreach ($p in $posList) { $hdr += ('{0,4}' -f $p) }
    Write-Host $hdr -ForegroundColor Gray
    Write-Host ('-' * $hdr.Length) -ForegroundColor Gray

    $winners = @()
    foreach ($d in $dlyList) {
        $row = ('{0,9} |' -f "$d")
        foreach ($p in $posList) {
            $r = Test-One $ip $ch @($p) $d $Timeout
            if ($r -like 'PASS*') { $row += '   P'; $winners += [pscustomobject]@{ Pos = $p; Delay = $d } }
            elseif ($r -like '*@READ*') { $row += '   .' }
            elseif ($r -like '*@CONNECT*') { $row += '   X' }
            else { $row += '   ?' }
            Start-Sleep -Milliseconds 100
        }
        Write-Host $row
    }
    Write-Host ('-' * $hdr.Length) -ForegroundColor Gray
    Write-Host 'P=通过   .=发完被RST(重组识别)   X=连不上   ?=其他' -ForegroundColor Gray
    Write-Host ''

    if (-not $winners.Count) {
        Write-Host '结论: 矩阵内没有任何组合通过 —— 用户态无解，走 GoodbyeDPI --disorder 或中转。' -ForegroundColor Red
        exit 1
    }

    Write-Host "共 $($winners.Count) 个组合通过，逐个复测 3 次判稳定性：" -ForegroundColor Cyan
    $stable = @()
    foreach ($w in $winners) {
        $ok = 0
        for ($i = 0; $i -lt 3; $i++) {
            $r = Test-One $ip $ch @($w.Pos) $w.Delay $Timeout
            if ($r -like 'PASS*') { $ok++ }
            Start-Sleep -Milliseconds 250
        }
        $tag = if ($ok -eq 3) { '稳定' } elseif ($ok -ge 2) { '较稳' } else { '偶发' }
        $color = if ($ok -eq 3) { 'Green' } elseif ($ok -ge 2) { 'Yellow' } else { 'DarkGray' }
        Write-Host ("  切点 {0,3}  间隔 {1,5}ms  ->  {2}/3  {3}" -f $w.Pos, $w.Delay, $ok, $tag) -ForegroundColor $color
        if ($ok -ge 2) { $stable += $w }
    }

    Write-Host ''
    if ($stable.Count) {
        $best = $stable | Sort-Object Delay, @{Expression = { [Math]::Abs($_.Pos - $midSplit) } } | Select-Object -First 1
        Write-Host "推荐参数: -Splits `"$($best.Pos)`" -DelayMs $($best.Delay)" -ForegroundColor Green
        Write-Host "复测命令: .\sni_probe.ps1 -Target $Target -Ip $ip -Splits `"$($best.Pos)`" -DelayMs $($best.Delay) -Repeat 5" -ForegroundColor Green
    }
    else {
        Write-Host '全部为偶发 —— 说明是概率性放行，不能作为长期方案。' -ForegroundColor Yellow
    }
    exit 0
}

# ---------- 模式 B：指定组合（含复测） ----------
$plans = @()
if ($Splits) {
    $custom = @($Splits.Split(',') | Where-Object { $_.Trim() -ne '' } | ForEach-Object { [int]$_.Trim() })
    $plans += @{ N = "自定义 $Splits  @${DelayMs}ms".PadRight(26); S = $custom; D = $DelayMs }
}
else {
    $plans += @{ N = '对照-一次性发出'.PadRight(26); S = @(); D = 0 }
    $plans += @{ N = '分片 1|rest'.PadRight(26); S = @(1); D = 30 }
    $plans += @{ N = "域名中段 $midSplit|rest".PadRight(26); S = @($midSplit); D = 30 }
    $plans += @{ N = "域名中段 $midSplit @800ms".PadRight(26); S = @($midSplit); D = 800 }
    $plans += @{ N = '分片 1 慢发 1200ms'.PadRight(26); S = @(1); D = 1200 }
    $plans += @{ N = '分片 5|rest'.PadRight(26); S = @(5); D = 30 }
}

$pass = 0; $rstCount = 0
foreach ($p in $plans) {
    $hits = 0
    $last = ''
    for ($i = 0; $i -lt $Repeat; $i++) {
        $last = Test-One $ip $ch $p.S $p.D $Timeout
        if ($last -like 'PASS*') { $hits++ }
        if ($i -lt $Repeat - 1) { Start-Sleep -Milliseconds 200 }
    }
    $color = if ($last -like 'PASS*') { 'Green' } elseif ($last -like 'BLOCKED*') { 'Red' } else { 'Yellow' }
    $suffix = if ($Repeat -gt 1) { "   [$hits/$Repeat]" } else { '' }
    Write-Host ("  {0}: {1}{2}" -f $p.N, $last, $suffix) -ForegroundColor $color
    if ($last -like 'PASS*') { $pass++ }
    if ($last -like 'BLOCKED@READ*' -or $last -like 'BLOCKED@WRITE*') { $rstCount++ }
    Start-Sleep -Milliseconds 200
}

Write-Host ('-' * 70)
if ($pass -gt 0) {
    Write-Host "结论: 有 $pass 种分段通过。" -ForegroundColor Green
    if ($Repeat -eq 1) { Write-Host "建议加 -Repeat 5 复测稳定性，或直接 -Scan 找最稳组合。" -ForegroundColor Green }
    exit 0
}
elseif ($rstCount -gt 0) {
    Write-Host '结论: TCP 通、数据发得出，RST 出现在读取阶段 -> 网关做了 TCP 流重组。' -ForegroundColor Yellow
    Write-Host '      用 -Scan 扫 [切点 x 间隔] 矩阵，找能打断重组的窗口。' -ForegroundColor Yellow
    exit 1
}
else {
    Write-Host '结论: 连接阶段失败，先排除 IP 选错。' -ForegroundColor Red
    exit 2
}
