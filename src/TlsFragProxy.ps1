#Requires -Version 5.1
<#
  tlsfrag-proxy.ps1  v4  —— 本地 TLS 分片 + 延时中继（纯 PowerShell + 内联 C#，零外部依赖）

  v4 修的三个问题：

  【1】只用一个 IP，没有回退
      ippure.com 解析到 172.67.139.58 和 104.21.79.4 两个 Cloudflare 地址。
      前者被校园网黑洞，v3 只取第一个且缓存了它，所以每次重试都撞同一个死 IP；
      Chrome 直连会自动换第二个，所以直连能开、走代理开不了。
      v4：解析出全部地址，逐个尝试，并把成功的那个记进策略文件，下次优先。

  【2】探测超时被误判为「被封」
      v3 的探测只要 1.5 秒没收到服务器首字节就标记 blocked，
      结果慢一点的站点（境外、高延迟）被永久打到分段模式。
      v4：区分 RST（真被封）与超时（只是慢）——超时不记录，保持连接继续转发。

  【3】不支持普通 HTTP 转发
      v3 只认 CONNECT，浏览器发过来的 http:// 请求（绝对 URI 形式）会被直接掐断。
      v4：支持 forward proxy，按 Host 建连后原样转发。

  用法：
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tlsfrag-proxy.ps1 -Delay 800 -Verbose
    ... -ConnectTimeout 4000 -ProbeTimeout 2500
    ... -ResetPolicy        清空已学到的策略
    ... -Only "douyin.com,taobao.com" -NoProbe    回到固定白名单模式
#>

param(
    [int]$Port = 8899,
    [int]$Delay = 800,
    [string]$Only,
    [int]$DnsTtl = 300,
    [int]$ConnectTimeout = 4000,
    [int]$ProbeTimeout = 2500,
    [switch]$NoProbe,
    [string]$PolicyFile,
    [switch]$ResetPolicy,
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'

if (-not $PolicyFile) { $PolicyFile = Join-Path $PSScriptRoot 'tlsfrag-policy.txt' }
if ($ResetPolicy -and (Test-Path $PolicyFile)) {
    Remove-Item $PolicyFile -Force
    Write-Host "已清空策略缓存: $PolicyFile" -ForegroundColor Yellow
}

$listMode = $PSBoundParameters.ContainsKey('Only')
if ($listMode -and $Only -eq '*') { $onlyList = @() }
elseif ($listMode) { $onlyList = @($Only.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ }) }
else { $onlyList = @() }

$adapt = (-not $NoProbe) -and (-not $listMode)

Write-Host ''
Write-Host '=== TLS 分片中继 v4 ===' -ForegroundColor Cyan
Write-Host "监听      : 127.0.0.1:$Port  (HTTP CONNECT + forward proxy + SOCKS5)" -ForegroundColor Gray
Write-Host "分段延时  : $Delay ms" -ForegroundColor Gray
Write-Host "建连超时  : ${ConnectTimeout}ms/IP   (多 IP 自动回退)" -ForegroundColor Gray
Write-Host "探测超时  : ${ProbeTimeout}ms   (超时不算被封，只有 RST 才算)" -ForegroundColor Gray
Write-Host "DNS 缓存  : ${DnsTtl}s" -ForegroundColor Gray
if ($adapt) { Write-Host '分流模式  : 自动探测（首访试直连，被 RST 才改分段，结论缓存）' -ForegroundColor Green }
elseif ($onlyList.Count -eq 0) { Write-Host '分流模式  : 全部分段（-Only "*"）' -ForegroundColor Yellow }
else { Write-Host ('分流模式  : 固定白名单 -> ' + ($onlyList -join ', ')) -ForegroundColor Gray }
Write-Host "策略缓存  : $PolicyFile" -ForegroundColor Gray
Write-Host ''

$csharp = @'
using System;
using System.IO;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Concurrent;
using System.Collections.Generic;

public class TlsFragProxy
{
    private int _port, _delay, _dnsTtl, _connTimeout, _probeTimeout;
    private string[] _only;
    private bool _adapt;
    private string _policyFile;
    private TcpListener _listener;
    private volatile bool _verbose;

    private class DnsEntry { public IPAddress[] Addrs; public DateTime Exp; }
    private static ConcurrentDictionary<string, DnsEntry> _dns =
        new ConcurrentDictionary<string, DnsEntry>();
    private class Pol { public string State = "unknown"; public string Ip = ""; }
    private static ConcurrentDictionary<string, Pol> _policy =
        new ConcurrentDictionary<string, Pol>();

    public TlsFragProxy(int port, int delay, string[] only, bool adapt,
                        int dnsTtl, int connTimeout, int probeTimeout,
                        string policyFile, bool verbose)
    {
        _port = port; _delay = delay; _only = only; _adapt = adapt;
        _dnsTtl = dnsTtl; _connTimeout = connTimeout; _probeTimeout = probeTimeout;
        _policyFile = policyFile; _verbose = verbose;
        LoadPolicy();
    }

    // ---------------- 策略持久化 ----------------
    private void LoadPolicy()
    {
        try
        {
            if (!File.Exists(_policyFile)) return;
            string[] lines = File.ReadAllLines(_policyFile);
            for (int i = 0; i < lines.Length; i++)
            {
                string[] p = lines[i].Split('\t');
                if (p.Length >= 2 && p[0].Trim().Length > 0)
                {
                    Pol pol = new Pol();
                    pol.State = p[1].Trim();
                    if (p.Length >= 3) pol.Ip = p[2].Trim();
                    _policy[p[0].Trim().ToLowerInvariant()] = pol;
                }
            }
            if (_verbose) Console.WriteLine("  [i] 载入策略 " + _policy.Count + " 条");
        }
        catch { }
    }

    private void SavePolicy()
    {
        try
        {
            List<string> outLines = new List<string>();
            foreach (KeyValuePair<string, Pol> kv in _policy)
                outLines.Add(kv.Key + "\t" + kv.Value.State + "\t" + kv.Value.Ip);
            File.WriteAllLines(_policyFile, outLines.ToArray());
        }
        catch { }
    }

    private Pol GetPol(string host)
    {
        Pol p;
        if (_policy.TryGetValue(host.ToLowerInvariant(), out p)) return p;
        return new Pol();
    }

    private void SetPol(string host, string state, string ip)
    {
        Pol p = new Pol();
        p.State = state; p.Ip = ip;
        _policy[host.ToLowerInvariant()] = p;
        SavePolicy();
    }

    public void StartAsync()
    {
        Thread t = new Thread(Loop);
        t.IsBackground = true;
        t.Start();
    }

    private void Loop()
    {
        _listener = new TcpListener(IPAddress.Loopback, _port);
        _listener.Start(1024);
        while (true)
        {
            TcpClient c = null;
            try { c = _listener.AcceptTcpClient(); }
            catch { continue; }
            TcpClient captured = c;
            ThreadPool.QueueUserWorkItem((WaitCallback)delegate(object st) { Handle(captured); });
        }
    }

    private static int Be16(byte[] b, int i) { return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF); }

    private bool InList(string host)
    {
        if (_only == null || _only.Length == 0) return true;
        string h = host.ToLowerInvariant();
        for (int i = 0; i < _only.Length; i++)
        {
            string s = _only[i];
            if (h == s || h.EndsWith("." + s)) return true;
        }
        return false;
    }

    // ---------------- DNS：返回全部地址 ----------------
    private IPAddress[] ResolveHost(string host)
    {
        string key = host.ToLowerInvariant();
        DnsEntry e;
        if (_dns.TryGetValue(key, out e) && e.Exp > DateTime.UtcNow) return e.Addrs;

        IPAddress[] all = Dns.GetHostAddresses(host);
        if (all == null || all.Length == 0) throw new Exception("no address");
        List<IPAddress> list = new List<IPAddress>();
        for (int i = 0; i < all.Length; i++) if (all[i].AddressFamily == AddressFamily.InterNetwork) list.Add(all[i]);
        if (list.Count == 0) for (int i = 0; i < all.Length; i++) list.Add(all[i]);

        IPAddress[] res = list.ToArray();
        DnsEntry ne = new DnsEntry();
        ne.Addrs = res; ne.Exp = DateTime.UtcNow.AddSeconds(_dnsTtl);
        _dns[key] = ne;
        return res;
    }

    // ---------------- 多 IP 回退 ----------------
    private TcpClient ConnectAny(IPAddress[] ips, int port, string preferIp, out IPAddress used)
    {
        used = null;
        List<IPAddress> order = new List<IPAddress>();
        if (preferIp != null && preferIp.Length > 0)
        {
            for (int i = 0; i < ips.Length; i++)
                if (ips[i].ToString() == preferIp) order.Add(ips[i]);
        }
        for (int i = 0; i < ips.Length; i++)
        {
            bool dup = false;
            for (int j = 0; j < order.Count; j++) if (order[j].Equals(ips[i])) { dup = true; break; }
            if (!dup) order.Add(ips[i]);
        }

        for (int i = 0; i < order.Count; i++)
        {
            TcpClient c = new TcpClient();
            c.NoDelay = true;
            try
            {
                IAsyncResult ar = c.BeginConnect(order[i], port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(_connTimeout))
                {
                    if (_verbose) Console.WriteLine("  [x] " + order[i] + ":" + port + " 超时，换下一个 IP");
                    try { c.Close(); } catch { }
                    continue;
                }
                c.EndConnect(ar);
                used = order[i];
                return c;
            }
            catch (Exception ex)
            {
                if (_verbose) Console.WriteLine("  [x] " + order[i] + ":" + port + " " + ex.GetType().Name + "，换下一个 IP");
                try { c.Close(); } catch { }
            }
        }
        return null;
    }

    // ---------------- 主处理 ----------------
    private void Handle(TcpClient client)
    {
        TcpClient upstream = null;
        try
        {
            client.NoDelay = true;
            NetworkStream cs = client.GetStream();
            int first = cs.ReadByte();
            if (first < 0) { client.Close(); return; }

            if (first == 0x05) { HandleSocks(cs, client); return; }

            // ---- HTTP：先读完整请求头，再判断是 CONNECT 还是普通转发 ----
            byte[] headerBytes;
            string headerText = ReadHeader(cs, first, out headerBytes);
            if (headerText == null) { client.Close(); return; }

            string firstLine = headerText.Split('\n')[0].Trim();
            string[] parts = firstLine.Split(' ');
            if (parts.Length < 3) { client.Close(); return; }

            string host;
            int port;

            if (parts[0] == "CONNECT")
            {
                string hostport = parts[1];
                int idx = hostport.LastIndexOf(':');
                if (idx <= 0) { client.Close(); return; }
                host = hostport.Substring(0, idx);
                if (!int.TryParse(hostport.Substring(idx + 1), out port) || port <= 0) port = 443;

                upstream = OpenUpstream(host, port);
                if (upstream == null) { Fail502(cs, client); return; }
                SendRaw(cs, Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\nProxy-Agent: TlsFragProxy\r\n\r\n"));
                DoTunnel(cs, upstream, host);
                return;
            }

            // ---- 普通 HTTP 转发（绝对 URI 形式）----
            Uri u = null;
            try { u = new Uri(parts[1]); } catch { }
            if (u == null || (u.Scheme != "http" && u.Scheme != "https"))
            {
                Fail502(cs, client);
                return;
            }
            host = u.Host;
            port = u.Port > 0 ? u.Port : 80;

            upstream = OpenUpstream(host, port);
            if (upstream == null) { Fail502(cs, client); return; }
            NetworkStream us = upstream.GetStream();
            if (_verbose) Console.WriteLine("  [HTTP] " + host + ":" + port);
            us.Write(headerBytes, 0, headerBytes.Length);
            us.Flush();
            RelayBoth(cs, us);
        }
        catch (Exception ex)
        {
            if (_verbose) Console.WriteLine("  [!] " + ex.GetType().Name + ": " + ex.Message);
            try { client.Close(); } catch { }
            if (upstream != null) { try { upstream.Close(); } catch { } }
        }
    }

    private TcpClient OpenUpstream(string host, int port)
    {
        IPAddress[] ips;
        try { ips = ResolveHost(host); }
        catch { return null; }

        Pol pol = GetPol(host);
        IPAddress used;
        TcpClient c = ConnectAny(ips, port, pol.Ip, out used);
        if (c == null)
        {
            if (_verbose) Console.WriteLine("  [X ] " + host + " 全部 IP 均不可达: " + JoinIps(ips));
            return null;
        }
        if (pol.Ip != used.ToString()) { pol.Ip = used.ToString(); _policy[host.ToLowerInvariant()] = pol; SavePolicy(); }
        return c;
    }

    private static string JoinIps(IPAddress[] ips)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ips.Length; i++) { if (i > 0) sb.Append(", "); sb.Append(ips[i]); }
        return sb.ToString();
    }

    private void Fail502(NetworkStream cs, TcpClient client)
    {
        try
        {
            byte[] b = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: TlsFragProxy\r\nContent-Length: 0\r\n\r\n");
            cs.Write(b, 0, b.Length);
            cs.Flush();
        }
        catch { }
        try { client.Close(); } catch { }
    }

    // ---- CONNECT 之后的隧道：决定直连还是分段 ----
    private void DoTunnel(NetworkStream cs, TcpClient upstream, string host)
    {
        NetworkStream us = upstream.GetStream();
        bool frag;

        if (!_adapt)
        {
            frag = InList(host);
            if (_verbose) Console.WriteLine((frag ? "  [FRAG] " : "  [PASS] ") + host);
            if (frag)
            {
                byte[] h = ReadFirstRecord(cs);
                if (h == null) return;
                RunFrag(cs, us, h);
            }
            else RelayBoth(cs, us);
            return;
        }

        Pol pol = GetPol(host);
        byte[] hello = ReadFirstRecord(cs);
        if (hello == null) return;

        if (pol.State == "blocked")
        {
            if (_verbose) Console.WriteLine("  [FRAG] " + host + "  (策略: 需分段)");
            RunFrag(cs, us, hello);
            return;
        }
        if (pol.State == "direct")
        {
            if (_verbose) Console.WriteLine("  [PASS] " + host + "  (策略: 直连)");
            us.Write(hello, 0, hello.Length);
            us.Flush();
            RelayBoth(cs, us);
            return;
        }

        // 首次遇到：先试直连，区分 RST 与超时
        bool rst = false;
        int head = -1;
        try
        {
            us.Write(hello, 0, hello.Length);
            us.Flush();
            us.ReadTimeout = _probeTimeout;
            head = us.ReadByte();
        }
        catch (IOException ex)
        {
            SocketException se = ex.InnerException as SocketException;
            if (se != null && se.SocketErrorCode == SocketError.ConnectionReset) rst = true;
            else if (se != null && se.SocketErrorCode == SocketError.ConnectionAborted) rst = true;
            else rst = false;
        }
        catch { rst = false; }
        try { us.ReadTimeout = Timeout.Infinite; } catch { }

        if (head >= 0)
        {
            SetPol(host, "direct", GetPol(host).Ip);
            if (_verbose) Console.WriteLine("  [PASS+] " + host + "  (探测: 直连可用)");
            cs.Write(new byte[] { (byte)head }, 0, 1); cs.Flush();
            RelayBoth(cs, us);
            return;
        }

        if (rst)
        {
            // 真被封
            SetPol(host, "blocked", GetPol(host).Ip);
            if (_verbose) Console.WriteLine("  [FRAG+] " + host + "  (探测: 直连被 RST，改用分段)");
            try { upstream.Close(); } catch { }
            TcpClient again = OpenUpstream(host, 443);
            if (again == null) { try { cs.Close(); } catch { } return; }
            RunFrag(cs, again.GetStream(), hello);
            return;
        }

        // 只是慢 / 超时：不记录状态，保持这条连接继续转发
        if (_verbose) Console.WriteLine("  [PASS?] " + host + "  (探测: 未响应但无 RST，按直连继续)");
        RelayBoth(cs, us);
    }

    private void HandleSocks(NetworkStream cs, TcpClient client)
    {
        TcpClient upstream = null;
        try
        {
            int nmethods = cs.ReadByte();
            if (nmethods < 0) { client.Close(); return; }
            byte[] ms = new byte[nmethods];
            int got = 0;
            while (got < nmethods) { int m = cs.Read(ms, got, nmethods - got); if (m <= 0) { client.Close(); return; } got += m; }
            cs.Write(new byte[] { 0x05, 0x00 }, 0, 2);
            cs.Flush();

            byte[] head = new byte[4];
            int r = 0;
            while (r < 4) { int m = cs.Read(head, r, 4 - r); if (m <= 0) { client.Close(); return; } r += m; }

            string host = null;
            int port = 0;
            int atyp = head[3];
            if (atyp == 0x01)
            {
                byte[] a = new byte[6];
                r = 0; while (r < 6) { int m = cs.Read(a, r, 6 - r); if (m <= 0) { client.Close(); return; } r += m; }
                host = new IPAddress(new byte[] { a[0], a[1], a[2], a[3] }).ToString();
                port = ((a[4] & 0xFF) << 8) | (a[5] & 0xFF);
            }
            else if (atyp == 0x03)
            {
                int ln = cs.ReadByte();
                if (ln < 0) { client.Close(); return; }
                byte[] nm = new byte[ln + 2];
                r = 0; while (r < nm.Length) { int m = cs.Read(nm, r, nm.Length - r); if (m <= 0) { client.Close(); return; } r += m; }
                host = Encoding.ASCII.GetString(nm, 0, ln);
                port = ((nm[ln] & 0xFF) << 8) | (nm[ln + 1] & 0xFF);
            }
            else
            {
                byte[] a = new byte[18];
                r = 0; while (r < 18) { int m = cs.Read(a, r, 18 - r); if (m <= 0) { client.Close(); return; } r += m; }
                byte[] ip6 = new byte[16];
                Array.Copy(a, 0, ip6, 0, 16);
                host = new IPAddress(ip6).ToString();
                port = ((a[16] & 0xFF) << 8) | (a[17] & 0xFF);
            }

            upstream = OpenUpstream(host, port);
            if (upstream == null)
            {
                cs.Write(new byte[] { 0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10);
                cs.Flush();
                client.Close();
                return;
            }
            cs.Write(new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10);
            cs.Flush();
            DoTunnel(cs, upstream, host);
        }
        catch
        {
            try { client.Close(); } catch { }
            if (upstream != null) { try { upstream.Close(); } catch { } }
        }
    }

    // ---------------- 读请求头 ----------------
    private string ReadHeader(NetworkStream cs, int firstByte, out byte[] raw)
    {
        raw = null;
        List<byte> buf = new List<byte>(512);
        buf.Add((byte)firstByte);
        byte[] one = new byte[1];
        while (buf.Count < 16384)
        {
            int n;
            try { n = cs.Read(one, 0, 1); } catch { return null; }
            if (n <= 0) return null;
            buf.Add(one[0]);
            if (buf.Count >= 4)
            {
                int c = buf.Count;
                if (buf[c - 4] == 13 && buf[c - 3] == 10 && buf[c - 2] == 13 && buf[c - 1] == 10) break;
            }
        }
        raw = buf.ToArray();
        return Encoding.ASCII.GetString(raw);
    }

    private byte[] ReadFirstRecord(NetworkStream cs)
    {
        byte[] acc = new byte[32768];
        int total = 0;
        try
        {
            cs.ReadTimeout = 2500;
            int n = cs.Read(acc, 0, acc.Length);
            if (n <= 0) return null;
            total = n;
            if (acc[0] == 0x16 && total >= 5)
            {
                int recLen = Be16(acc, 3) + 5;
                if (recLen > total && recLen <= acc.Length)
                {
                    try
                    {
                        while (total < recLen)
                        {
                            int m = cs.Read(acc, total, recLen - total);
                            if (m <= 0) break;
                            total += m;
                        }
                    }
                    catch { }
                }
            }
            cs.ReadTimeout = Timeout.Infinite;
            byte[] res = new byte[total];
            Array.Copy(acc, res, total);
            return res;
        }
        catch
        {
            try { cs.ReadTimeout = Timeout.Infinite; } catch { }
            if (total > 0) { byte[] res = new byte[total]; Array.Copy(acc, res, total); return res; }
            return null;
        }
    }

    private static int FindSniSplit(byte[] b, int len)
    {
        if (len < 44) return -1;
        if (b[0] != 0x16) return -1;
        if (b[5] != 0x01) return -1;
        int hsLen = ((b[6] & 0xFF) << 16) | ((b[7] & 0xFF) << 8) | (b[8] & 0xFF);
        int end = 9 + hsLen;
        if (end > len) end = len;

        int p = 9 + 2 + 32;
        if (p >= end) return -1;
        p += 1 + b[p];
        if (p + 2 > end) return -1;
        p += 2 + Be16(b, p);
        if (p + 1 > end) return -1;
        p += 1 + b[p];
        if (p + 2 > end) return -1;
        int extTotal = Be16(b, p); p += 2;
        int extEnd = p + extTotal;
        if (extEnd > end) extEnd = end;

        while (p + 4 <= extEnd)
        {
            int type = Be16(b, p);
            int elen = Be16(b, p + 2);
            int d = p + 4;
            if (type == 0x0000)
            {
                if (d + 5 > extEnd) return -1;
                int nameLen = Be16(b, d + 3);
                int nameOff = d + 5;
                if (nameOff + nameLen > extEnd) return -1;
                int mid = nameOff + (nameLen / 2);
                if (mid <= 0 || mid >= len) return -1;
                return mid;
            }
            p = d + elen;
        }
        return -1;
    }

    private void RunFrag(NetworkStream cs, NetworkStream us, byte[] hello)
    {
        int split = FindSniSplit(hello, hello.Length);
        if (split <= 0 || split >= hello.Length) split = hello.Length / 2;
        us.Write(hello, 0, split);
        us.Flush();
        if (_delay > 0) Thread.Sleep(_delay);
        us.Write(hello, split, hello.Length - split);
        us.Flush();
        RelayBoth(cs, us);
    }

    private void RelayBoth(NetworkStream cs, NetworkStream us)
    {
        Thread up = new Thread((ThreadStart)delegate { Pump(cs, us); });
        Thread down = new Thread((ThreadStart)delegate { Pump(us, cs); });
        up.IsBackground = true; down.IsBackground = true;
        up.Start(); down.Start();
        up.Join();
        try { us.Close(); } catch { }
        try { cs.Close(); } catch { }
    }

    private void SendRaw(NetworkStream cs, byte[] data)
    {
        if (data == null || data.Length == 0) return;
        cs.Write(data, 0, data.Length);
        cs.Flush();
    }

    private void Pump(NetworkStream src, NetworkStream dst)
    {
        byte[] buf = new byte[32768];
        try
        {
            src.ReadTimeout = Timeout.Infinite;
            while (true)
            {
                int n = src.Read(buf, 0, buf.Length);
                if (n <= 0) break;
                dst.Write(buf, 0, n);
            }
        }
        catch { }
        try { dst.Close(); } catch { }
    }
}
'@

Add-Type -TypeDefinition $csharp -Language CSharp -ErrorAction Stop

$proxy = New-Object TlsFragProxy -ArgumentList `
    $Port, $Delay, ([string[]]$onlyList), [bool]$adapt, $DnsTtl, $ConnectTimeout, $ProbeTimeout, $PolicyFile, [bool]$Verbose
$proxy.StartAsync()

Write-Host '已启动。系统代理 / 浏览器代理填 127.0.0.1:' -NoNewline -ForegroundColor Green
Write-Host "$Port" -ForegroundColor Yellow
Write-Host '标记: [FRAG] 分段  [PASS] 直连  [PASS?] 探测无响应但未 RST  [HTTP] 普通转发  [x] 换 IP  [X ] 全 IP 不可达' -ForegroundColor Gray
Write-Host '按 Ctrl+C 停止。' -ForegroundColor Gray
Write-Host ''

try { while ($true) { Start-Sleep -Seconds 3600 } }
finally { Write-Host '已停止。' -ForegroundColor Gray }
