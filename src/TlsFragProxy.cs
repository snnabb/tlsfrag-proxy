using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace TlsFrag
{
    // ===================== 配置 =====================
    public class Cfg
    {
        public int Port = 8899;
        public int Delay = 800;
        public int DnsTtl = 300;
        public int ConnectTimeout = 4000;
        public int ProbeTimeout = 2500;
        public bool ManageSystemProxy = true;
        public bool ResetPolicy = false;
        public string BaseDir;
        public string PolicyFile { get { return Path.Combine(BaseDir, "policy.txt"); } }
        public string LogFile { get { return Path.Combine(BaseDir, "TlsFragProxy.log"); } }
        public string BackupFile { get { return Path.Combine(BaseDir, "proxy-backup.txt"); } }
    }

    // ===================== 日志 =====================
    public static class Log
    {
        private static object _lock = new object();
        public static string FilePath = "TlsFragProxy.log";
        public static void W(string s)
        {
            string line = DateTime.Now.ToString("HH:mm:ss") + "  " + s;
            lock (_lock)
            {
                try
                {
                    FileInfo fi = new FileInfo(FilePath);
                    if (fi.Exists && fi.Length > 2 * 1024 * 1024) File.WriteAllText(FilePath, "");
                    File.AppendAllText(FilePath, line + "\r\n", Encoding.Default);
                }
                catch { }
            }
        }
    }

    // ===================== 代理引擎 =====================
    public class Engine
    {
        private Cfg _c;
        private TcpListener _listener;
        private volatile bool _running;
        public long ConnTotal = 0, FragTotal = 0, FailTotal = 0;

        private class DnsEntry { public IPAddress[] Addrs; public DateTime Exp; }
        private static ConcurrentDictionary<string, DnsEntry> _dns = new ConcurrentDictionary<string, DnsEntry>();
        private class Pol { public string State = "unknown"; public string Ip = ""; }
        private static ConcurrentDictionary<string, Pol> _policy = new ConcurrentDictionary<string, Pol>();

        public Engine(Cfg c) { _c = c; LoadPolicy(); }

        private void LoadPolicy()
        {
            try
            {
                if (!File.Exists(_c.PolicyFile)) return;
                foreach (string line in File.ReadAllLines(_c.PolicyFile, Encoding.Default))
                {
                    string[] p = line.Split('\t');
                    if (p.Length >= 2 && p[0].Trim().Length > 0)
                    {
                        Pol pol = new Pol();
                        pol.State = p[1].Trim();
                        if (p.Length >= 3) pol.Ip = p[2].Trim();
                        _policy[p[0].Trim().ToLowerInvariant()] = pol;
                    }
                }
                Log.W("载入策略 " + _policy.Count + " 条");
            }
            catch { }
        }

        private static readonly object _policyLock = new object();

        private void SavePolicy()
        {
            lock (_policyLock)
            {
                try
                {
                    List<string> lines = new List<string>();
                    foreach (KeyValuePair<string, Pol> kv in _policy) lines.Add(kv.Key + "\t" + kv.Value.State + "\t" + kv.Value.Ip);
                    string tmp = _c.PolicyFile + ".tmp";
                    File.WriteAllLines(tmp, lines.ToArray(), Encoding.Default);
                    if (File.Exists(_c.PolicyFile)) File.Delete(_c.PolicyFile);
                    File.Move(tmp, _c.PolicyFile);
                }
                catch { }
            }
        }

        public void ResetPolicy()
        {
            _policy.Clear();
            try { if (File.Exists(_c.PolicyFile)) File.Delete(_c.PolicyFile); } catch { }
        }

        private Pol GetPol(string host)
        {
            Pol p;
            if (_policy.TryGetValue(host.ToLowerInvariant(), out p)) return p;
            return new Pol();
        }

        private void SetPol(string host, string state, string ip)
        {
            Pol p = new Pol(); p.State = state; p.Ip = ip;
            _policy[host.ToLowerInvariant()] = p;
            SavePolicy();
        }

        public void Start()
        {
            _listener = new TcpListener(IPAddress.Loopback, _c.Port);
            _listener.Start(1024);
            _running = true;
            Thread t = new Thread(Loop);
            t.IsBackground = true;
            t.Start();
            Log.W("监听 127.0.0.1:" + _c.Port + "  delay=" + _c.Delay + "ms");
        }

        public void Stop()
        {
            _running = false;
            try { if (_listener != null) _listener.Stop(); } catch { }
            Log.W("已停止");
        }

        private void Loop()
        {
            while (_running)
            {
                TcpClient c = null;
                try { c = _listener.AcceptTcpClient(); }
                catch { break; }
                TcpClient cap = c;
                ThreadPool.QueueUserWorkItem(delegate(object st) { Handle(cap); });
            }
        }

        private static int Be16(byte[] b, int i) { return ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF); }

        private IPAddress[] ResolveHost(string host)
        {
            string key = host.ToLowerInvariant();
            DnsEntry e;
            if (_dns.TryGetValue(key, out e) && e.Exp > DateTime.UtcNow) return e.Addrs;
            IPAddress[] all = Dns.GetHostAddresses(host);
            if (all == null || all.Length == 0) throw new Exception("no address");
            List<IPAddress> l = new List<IPAddress>();
            for (int i = 0; i < all.Length; i++) if (all[i].AddressFamily == AddressFamily.InterNetwork) l.Add(all[i]);
            if (l.Count == 0) for (int i = 0; i < all.Length; i++) l.Add(all[i]);
            IPAddress[] res = l.ToArray();
            DnsEntry ne = new DnsEntry(); ne.Addrs = res; ne.Exp = DateTime.UtcNow.AddSeconds(_c.DnsTtl);
            _dns[key] = ne;
            return res;
        }

        private TcpClient ConnectAny(IPAddress[] ips, int port, string preferIp)
        {
            List<IPAddress> order = new List<IPAddress>();
            if (!string.IsNullOrEmpty(preferIp))
                for (int i = 0; i < ips.Length; i++) if (ips[i].ToString() == preferIp) order.Add(ips[i]);
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
                    if (!ar.AsyncWaitHandle.WaitOne(_c.ConnectTimeout))
                    {
                        Log.W("  [x] " + order[i] + ":" + port + " 超时，换下一个 IP");
                        try { c.Close(); } catch { }
                        continue;
                    }
                    c.EndConnect(ar);
                    return c;
                }
                catch (Exception ex)
                {
                    Log.W("  [x] " + order[i] + ":" + port + " " + ex.GetType().Name + "，换下一个 IP");
                    try { c.Close(); } catch { }
                }
            }
            return null;
        }

        private TcpClient OpenUpstream(string host, int port)
        {
            IPAddress[] ips;
            try { ips = ResolveHost(host); }
            catch { Log.W("  [X ] " + host + " 解析失败"); FailTotal++; return null; }

            Pol pol = GetPol(host);
            TcpClient c = ConnectAny(ips, port, pol.Ip);
            if (c == null)
            {
                Log.W("  [X ] " + host + " 全部 IP 不可达");
                FailTotal++;
                return null;
            }
            string used = c.Client.RemoteEndPoint.ToString();
            int k = used.LastIndexOf(':');
            if (k > 0) used = used.Substring(0, k);
            if (pol.Ip != used) { pol.Ip = used; _policy[host.ToLowerInvariant()] = pol; SavePolicy(); }
            return c;
        }

        private void Handle(TcpClient client)
        {
            TcpClient upstream = null;
            try
            {
                client.NoDelay = true;
                NetworkStream cs = client.GetStream();
                int first = cs.ReadByte();
                if (first < 0) { client.Close(); return; }
                ConnTotal++;

                if (first == 0x05) { HandleSocks(cs, client); return; }

                byte[] hb;
                string ht = ReadHeader(cs, first, out hb);
                if (ht == null) { client.Close(); return; }

                string[] parts = ht.Split('\n')[0].Trim().Split(' ');
                if (parts.Length < 3) { client.Close(); return; }

                if (parts[0] == "CONNECT")
                {
                    string hp = parts[1];
                    int idx = hp.LastIndexOf(':');
                    if (idx <= 0) { client.Close(); return; }
                    string host = hp.Substring(0, idx);
                    int port;
                    if (!int.TryParse(hp.Substring(idx + 1), out port) || port <= 0) port = 443;

                    upstream = OpenUpstream(host, port);
                    if (upstream == null) { Fail502(cs, client); return; }
                    byte[] ok = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\nProxy-Agent: TlsFragProxy\r\n\r\n");
                    cs.Write(ok, 0, ok.Length); cs.Flush();
                    DoTunnel(cs, upstream, host, port);
                    return;
                }

                Uri u = null;
                try { u = new Uri(parts[1]); } catch { }
                if (u == null) { Fail502(cs, client); return; }
                int p2 = u.Port > 0 ? u.Port : 80;
                upstream = OpenUpstream(u.Host, p2);
                if (upstream == null) { Fail502(cs, client); return; }
                NetworkStream us = upstream.GetStream();
                Log.W("  [HTTP] " + u.Host + ":" + p2);
                us.Write(hb, 0, hb.Length); us.Flush();
                RelayBoth(cs, us);
            }
            catch (Exception ex)
            {
                Log.W("  [!] " + ex.GetType().Name + ": " + ex.Message);
                FailTotal++;
                try { client.Close(); } catch { }
                if (upstream != null) { try { upstream.Close(); } catch { } }
            }
        }

        private void DoTunnel(NetworkStream cs, TcpClient upstream, string host, int port)
        {
            NetworkStream us = upstream.GetStream();
            byte[] hello = ReadFirstRecord(cs);
            if (hello == null) return;

            Pol pol = GetPol(host);
            if (pol.State == "blocked")
            {
                Log.W("  [FRAG] " + host + "  (策略:需分段)");
                FragTotal++;
                RunFrag(cs, us, hello);
                return;
            }
            if (pol.State == "direct")
            {
                us.Write(hello, 0, hello.Length); us.Flush();
                RelayBoth(cs, us);
                return;
            }

            bool rst = false;
            int head = -1;
            try
            {
                us.Write(hello, 0, hello.Length); us.Flush();
                us.ReadTimeout = _c.ProbeTimeout;
                head = us.ReadByte();
            }
            catch (IOException ex)
            {
                SocketException se = ex.InnerException as SocketException;
                if (se != null && (se.SocketErrorCode == SocketError.ConnectionReset ||
                                   se.SocketErrorCode == SocketError.ConnectionAborted)) rst = true;
            }
            catch { }
            try { us.ReadTimeout = Timeout.Infinite; } catch { }

            // 0x16 = ServerHello：直连确实可用，可以记录
            // 0x15 = TLS Alert：可能来自服务器，也可能来自网关自己，无法区分；
            //        按「需分段」处理更安全 —— 分段对服务器端的真实拒绝没有副作用
            // 其它首字节：不足以判定，只放行、不记录结论
            if (head == 0x16)
            {
                SetPol(host, "direct", GetPol(host).Ip);
                Log.W("  [PASS] " + host + "  (探测:直连收到 ServerHello，已记录)");
                cs.Write(new byte[] { (byte)head }, 0, 1); cs.Flush();
                RelayBoth(cs, us);
                return;
            }
            if (head >= 0 && head != 0x15)
            {
                Log.W("  [PASS] " + host + "  (探测:首字节 0x" + head.ToString("X2") + "，不记录结论)");
                cs.Write(new byte[] { (byte)head }, 0, 1); cs.Flush();
                RelayBoth(cs, us);
                return;
            }
            if (head == 0x15) rst = true;

            if (rst)
            {
                SetPol(host, "blocked", GetPol(host).Ip);
                Log.W("  [FRAG] " + host + "  (探测:" + (head == 0x15 ? "直连收到 TLS Alert" : "直连被 RST") + "，改用分段)");
                FragTotal++;
                try { upstream.Close(); } catch { }
                TcpClient again = OpenUpstream(host, port);
                if (again == null) { try { cs.Close(); } catch { } return; }
                RunFrag(cs, again.GetStream(), hello);
                return;
            }

            Log.W("  [PASS] " + host + "  (探测:无响应但未 RST，按直连继续)");
            RelayBoth(cs, us);
        }

        private void HandleSocks(NetworkStream cs, TcpClient client)
        {
            TcpClient upstream = null;
            try
            {
                int nm = cs.ReadByte();
                if (nm < 0) { client.Close(); return; }
                byte[] ms = new byte[nm];
                int got = 0;
                while (got < nm) { int m = cs.Read(ms, got, nm - got); if (m <= 0) { client.Close(); return; } got += m; }
                cs.Write(new byte[] { 0x05, 0x00 }, 0, 2); cs.Flush();

                byte[] head = new byte[4];
                int r = 0;
                while (r < 4) { int m = cs.Read(head, r, 4 - r); if (m <= 0) { client.Close(); return; } r += m; }

                string host = null; int port = 0;
                int atyp = head[3];
                if (atyp == 0x01)
                {
                    byte[] a = new byte[6]; r = 0;
                    while (r < 6) { int m = cs.Read(a, r, 6 - r); if (m <= 0) { client.Close(); return; } r += m; }
                    host = new IPAddress(new byte[] { a[0], a[1], a[2], a[3] }).ToString();
                    port = ((a[4] & 0xFF) << 8) | (a[5] & 0xFF);
                }
                else if (atyp == 0x03)
                {
                    int ln = cs.ReadByte();
                    if (ln < 0) { client.Close(); return; }
                    byte[] nm2 = new byte[ln + 2]; r = 0;
                    while (r < nm2.Length) { int m = cs.Read(nm2, r, nm2.Length - r); if (m <= 0) { client.Close(); return; } r += m; }
                    host = Encoding.ASCII.GetString(nm2, 0, ln);
                    port = ((nm2[ln] & 0xFF) << 8) | (nm2[ln + 1] & 0xFF);
                }
                else
                {
                    byte[] a = new byte[18]; r = 0;
                    while (r < 18) { int m = cs.Read(a, r, 18 - r); if (m <= 0) { client.Close(); return; } r += m; }
                    byte[] ip6 = new byte[16]; Array.Copy(a, 0, ip6, 0, 16);
                    host = new IPAddress(ip6).ToString();
                    port = ((a[16] & 0xFF) << 8) | (a[17] & 0xFF);
                }

                upstream = OpenUpstream(host, port);
                if (upstream == null)
                {
                    cs.Write(new byte[] { 0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10);
                    cs.Flush(); client.Close(); return;
                }
                cs.Write(new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10);
                cs.Flush();
                DoTunnel(cs, upstream, host, port);
            }
            catch
            {
                try { client.Close(); } catch { }
                if (upstream != null) { try { upstream.Close(); } catch { } }
            }
        }

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

        // 读取一条完整的 ClientHello。RFC 8446 允许握手消息跨多个 TLS record，
        // 所以这里按 record 循环累积，直到握手消息声明的长度收满为止。
        private byte[] ReadFirstRecord(NetworkStream cs)
        {
            byte[] buf = new byte[32768];
            int hdr = 0;        // 当前 record 头偏移
            int pos = 0;        // 已读字节数
            int payload = 0;    // 已收握手负载字节数
            int hsDeclared = -1;
            try
            {
                cs.ReadTimeout = 2500;
                while (hdr + 5 <= buf.Length)
                {
                    while (pos < hdr + 5)
                    {
                        int n = cs.Read(buf, pos, hdr + 5 - pos);
                        if (n <= 0) { cs.ReadTimeout = Timeout.Infinite; return Trim(buf, pos); }
                        pos += n;
                    }
                    if (hdr == 0 && buf[0] != 0x16) break;      // 不是 TLS 握手
                    int recLen = Be16(buf, hdr + 3) + 5;
                    if (recLen < 5 || hdr + recLen > buf.Length) break;
                    while (pos < hdr + recLen)
                    {
                        int n = cs.Read(buf, pos, hdr + recLen - pos);
                        if (n <= 0) { cs.ReadTimeout = Timeout.Infinite; return Trim(buf, pos); }
                        pos += n;
                    }
                    payload += recLen - 5;
                    if (hsDeclared < 0 && pos >= 9)
                        hsDeclared = 4 + (((buf[6] & 0xFF) << 16) | ((buf[7] & 0xFF) << 8) | (buf[8] & 0xFF));
                    if (hsDeclared >= 0 && payload >= hsDeclared) break;
                    hdr += recLen;
                }
                cs.ReadTimeout = Timeout.Infinite;
                return Trim(buf, pos);
            }
            catch
            {
                try { cs.ReadTimeout = Timeout.Infinite; } catch { }
                return Trim(buf, pos);
            }
        }

        private static byte[] Trim(byte[] buf, int len)
        {
            if (len <= 0) return null;
            byte[] res = new byte[len];
            Array.Copy(buf, res, len);
            return res;
        }

        private static int FindSniSplit(byte[] b, int len)
        {
            if (len < 44) return -1;
            if (b[0] != 0x16 || b[5] != 0x01) return -1;
            int hsLen = ((b[6] & 0xFF) << 16) | ((b[7] & 0xFF) << 8) | (b[8] & 0xFF);
            int end = 9 + hsLen; if (end > len) end = len;
            int p = 9 + 2 + 32;
            if (p >= end) return -1;
            p += 1 + b[p];
            if (p + 2 > end) return -1;
            p += 2 + Be16(b, p);
            if (p + 1 > end) return -1;
            p += 1 + b[p];
            if (p + 2 > end) return -1;
            int extTotal = Be16(b, p); p += 2;
            int extEnd = p + extTotal; if (extEnd > end) extEnd = end;
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
            // FindSniSplit 假设握手字节连续，只在第一个 record 范围内成立。
            // 若 SNI 落在后续 record，退化为第一 record 中点（仍能保证两段都不含完整域名）。
            int firstRec = (hello.Length >= 5) ? (Be16(hello, 3) + 5) : hello.Length;
            if (firstRec > hello.Length || firstRec < 5) firstRec = hello.Length;
            int split = FindSniSplit(hello, firstRec);
            if (split <= 0) split = FindSniSplit(hello, hello.Length);
            if (split <= 0 || split >= hello.Length) split = firstRec > 10 ? firstRec / 2 : hello.Length / 2;
            us.Write(hello, 0, split); us.Flush();
            if (_c.Delay > 0) Thread.Sleep(_c.Delay);
            us.Write(hello, split, hello.Length - split); us.Flush();
            RelayBoth(cs, us);
        }

        private void RelayBoth(NetworkStream cs, NetworkStream us)
        {
            Thread up = new Thread(delegate() { Pump(cs, us); }, 256 * 1024);
            Thread down = new Thread(delegate() { Pump(us, cs); }, 256 * 1024);
            up.IsBackground = true; down.IsBackground = true;
            up.Start(); down.Start();
            up.Join();
            try { us.Close(); } catch { }
            try { cs.Close(); } catch { }
        }

        private void Fail502(NetworkStream cs, TcpClient client)
        {
            try
            {
                byte[] b = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: TlsFragProxy\r\nContent-Length: 0\r\n\r\n");
                cs.Write(b, 0, b.Length); cs.Flush();
            }
            catch { }
            try { client.Close(); } catch { }
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

    // ===================== 系统代理 =====================
    public static class SysProxy
    {
        private const string Key = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool InternetSetOption(IntPtr h, int opt, IntPtr buf, int len);

        private static void Refresh()
        {
            InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
        }

        public class Snapshot
        {
            public int Enable;
            public string Server;
            public string Override;
            public bool Valid;
        }

        public static Snapshot Capture()
        {
            Snapshot s = new Snapshot();
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(Key, false))
                {
                    if (k != null)
                    {
                        object e = k.GetValue("ProxyEnable");
                        s.Enable = (e == null) ? 0 : Convert.ToInt32(e);
                        s.Server = k.GetValue("ProxyServer") as string;
                        s.Override = k.GetValue("ProxyOverride") as string;
                        s.Valid = true;
                    }
                }
            }
            catch { }
            return s;
        }

        public static string Describe()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(Key, false))
                {
                    if (k == null) return "无法读取注册表";
                    object e = k.GetValue("ProxyEnable");
                    int en = (e == null) ? 0 : Convert.ToInt32(e);
                    string s = k.GetValue("ProxyServer") as string;
                    if (en == 1) return "开 -> " + ((s == null || s.Length == 0) ? "(空)" : s);
                    return "关";
                }
            }
            catch (Exception ex) { return "读取失败: " + ex.Message; }
        }

        public static bool IsPointingTo(int port)
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(Key, false))
                {
                    if (k == null) return false;
                    object e = k.GetValue("ProxyEnable");
                    int en = (e == null) ? 0 : Convert.ToInt32(e);
                    string s = k.GetValue("ProxyServer") as string;
                    return en == 1 && s != null && s.IndexOf("127.0.0.1:" + port) >= 0;
                }
            }
            catch { return false; }
        }

        public static string BackupPath;

        public static Snapshot LoadBackup()
        {
            try
            {
                if (BackupPath == null || !File.Exists(BackupPath)) return null;
                string[] l = File.ReadAllLines(BackupPath, Encoding.Default);
                if (l.Length < 1) return null;
                Snapshot s = new Snapshot();
                s.Enable = int.Parse(l[0].Trim());
                s.Server = l.Length > 1 ? l[1] : null;
                s.Override = l.Length > 2 ? l[2] : null;
                s.Valid = true;
                return s;
            }
            catch { return null; }
        }

        // 把当前系统代理设置备份到文件，供崩溃后下次启动恢复
        public static void SaveBackup(Snapshot s)
        {
            try
            {
                if (BackupPath == null || s == null || !s.Valid) return;
                File.WriteAllLines(BackupPath, new string[] {
                    s.Enable.ToString(),
                    s.Server == null ? "" : s.Server,
                    s.Override == null ? "" : s.Override
                }, Encoding.Default);
            }
            catch { }
        }

        public static void DropBackup()
        {
            try { if (BackupPath != null && File.Exists(BackupPath)) File.Delete(BackupPath); } catch { }
        }

        public static void Apply(int port)
        {
            SaveBackup(Capture());
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(Key, true))
            {
                if (k == null) return;
                k.SetValue("ProxyServer", "127.0.0.1:" + port, RegistryValueKind.String);
                k.SetValue("ProxyOverride",
                    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*;<local>",
                    RegistryValueKind.String);
                k.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
            }
            Refresh();
        }

        public static void Restore(Snapshot s)
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(Key, true))
                {
                    if (k == null) return;
                    if (!s.Valid) { k.SetValue("ProxyEnable", 0, RegistryValueKind.DWord); }
                    else
                    {
                        k.SetValue("ProxyEnable", s.Enable, RegistryValueKind.DWord);
                        if (s.Server != null) k.SetValue("ProxyServer", s.Server, RegistryValueKind.String);
                        if (s.Override != null) k.SetValue("ProxyOverride", s.Override, RegistryValueKind.String);
                    }
                }
            }
            catch { }
            DropBackup();
            Refresh();
        }
    }

    // ===================== 托盘 =====================
    public class TrayApp : ApplicationContext
    {
        private Cfg _c;
        private Engine _e;
        private NotifyIcon _icon;
        private SysProxy.Snapshot _snap;
        private ToolStripMenuItem _autoItem;
        private ToolStripMenuItem _proxyItem;
        private bool _warned = false;
        private string _lastSeen = "";
        private ToolStripMenuItem _statusItem;

        public TrayApp(Cfg c)
        {
            _c = c;
            SysProxy.BackupPath = _c.BackupFile;

            // 上次被强杀时系统代理可能仍指向我们的端口，先从备份恢复
            if (SysProxy.IsPointingTo(_c.Port))
            {
                SysProxy.Snapshot prev = SysProxy.LoadBackup();
                if (prev != null)
                {
                    SysProxy.Restore(prev);
                    Log.W("检测到上次异常退出残留的系统代理，已从 proxy-backup.txt 恢复");
                }
                else
                {
                    SysProxy.Snapshot off = new SysProxy.Snapshot();
                    off.Valid = true;
                    off.Enable = 0;
                    SysProxy.Restore(off);
                    Log.W("检测到上次异常退出残留的系统代理，无备份可用，已关闭代理");
                }
            }
            _snap = SysProxy.Capture();

            _e = new Engine(_c);
            try { _e.Start(); }
            catch (Exception ex)
            {
                MessageBox.Show("端口 " + _c.Port + " 启动失败：" + ex.Message, "TlsFragProxy",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.Exit(1);
            }

            if (_c.ManageSystemProxy)
            {
                SysProxy.Apply(_c.Port);
                Log.W("系统代理写入回读: " + SysProxy.Describe());
            }

            ContextMenuStrip menu = new ContextMenuStrip();
            _statusItem = new ToolStripMenuItem("运行中  127.0.0.1:" + _c.Port + "  延时 " + _c.Delay + "ms");
            _statusItem.Enabled = false;
            menu.Items.Add(_statusItem);
            menu.Items.Add(new ToolStripSeparator());

            ToolStripMenuItem logItem = new ToolStripMenuItem("查看日志");
            logItem.Click += delegate { OpenLog(); };
            menu.Items.Add(logItem);

            ToolStripMenuItem policyItem = new ToolStripMenuItem("重置学习结果");
            policyItem.Click += delegate
            {
                if (MessageBox.Show("清空已学到的域名策略？下次访问会重新探测。", "TlsFragProxy",
                        MessageBoxButtons.OKCancel, MessageBoxIcon.Question) == DialogResult.OK)
                {
                    _e.ResetPolicy();
                    Log.W("策略已重置");
                }
            };
            menu.Items.Add(policyItem);

            _autoItem = new ToolStripMenuItem("开机自动启动");
            _autoItem.CheckOnClick = true;
            _autoItem.Checked = IsAutoStart();
            _autoItem.Click += delegate { SetAutoStart(_autoItem.Checked); };
            menu.Items.Add(_autoItem);

            _proxyItem = new ToolStripMenuItem("系统代理: " + SysProxy.Describe());
            _proxyItem.Click += delegate
            {
                if (SysProxy.IsPointingTo(_c.Port)) SysProxy.Restore(_snap);
                else SysProxy.Apply(_c.Port);
                _proxyItem.Text = "系统代理: " + SysProxy.Describe();
                Log.W("手动切换系统代理 -> " + SysProxy.Describe());
            };
            menu.Items.Add(_proxyItem);

            menu.Items.Add(new ToolStripSeparator());
            ToolStripMenuItem exitItem = new ToolStripMenuItem("退出");
            exitItem.Click += delegate { ExitApp(); };
            menu.Items.Add(exitItem);

            _icon = new NotifyIcon();
            _icon.Icon = LoadTrayIcon() ?? SystemIcons.Application;
            _icon.Text = "TlsFragProxy  " + _c.Port;
            _icon.ContextMenuStrip = menu;
            _icon.Visible = true;
            _icon.DoubleClick += delegate { OpenLog(); };
            _icon.BalloonTipTitle = "TlsFragProxy 已启动";
            _icon.BalloonTipText = "代理 127.0.0.1:" + _c.Port + (_c.ManageSystemProxy ? "，系统代理已设置" : "，未改系统代理");
            _icon.ShowBalloonTip(2500);

            System.Windows.Forms.Timer wt = new System.Windows.Forms.Timer();
            wt.Interval = 4000;
            wt.Tick += delegate { CheckProxy(); };
            wt.Start();
            _lastSeen = SysProxy.Describe();

            Log.W("启动完成  管理系统代理=" + _c.ManageSystemProxy);
        }

        private void CheckProxy()
        {
            string now = SysProxy.Describe();
            if (now != _lastSeen)
            {
                _lastSeen = now;
                Log.W("系统代理状态变化: " + now);
                if (_proxyItem != null) _proxyItem.Text = "系统代理: " + now;
            }
            if (_c.ManageSystemProxy && !SysProxy.IsPointingTo(_c.Port))
            {
                if (!_warned)
                {
                    _warned = true;
                    Log.W("[!] 系统代理不是本程序的值，可能被其他代理软件或安全软件改掉了。当前: " + now);
                    if (_icon != null)
                    {
                        _icon.BalloonTipTitle = "系统代理被改动";
                        _icon.BalloonTipText = "当前: " + now + "\n右键托盘 -> 点\"系统代理\"可重新设置";
                        _icon.ShowBalloonTip(4000);
                    }
                }
            }
            else _warned = false;
        }

        private static Icon LoadTrayIcon()
        {
            try { return Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch { return null; }
        }

        private void OpenLog()
        {
            try { Process.Start("notepad.exe", _c.LogFile); } catch { }
        }

        private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string RunName = "TlsFragProxy";

        private bool IsAutoStart()
        {
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(RunKey, false))
                return k != null && k.GetValue(RunName) != null;
        }

        private void SetAutoStart(bool on)
        {
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(RunKey, true))
            {
                if (k == null) return;
                if (on)
                {
                    string exe = Application.ExecutablePath;
                    StringBuilder sb = new StringBuilder();
                    sb.Append("\"").Append(exe).Append("\"");
                    string[] args = Environment.GetCommandLineArgs();
                    for (int i = 1; i < args.Length; i++) sb.Append(" ").Append(args[i]);
                    k.SetValue(RunName, sb.ToString());
                }
                else k.DeleteValue(RunName, false);
            }
        }

        private void ExitApp()
        {
            Log.W("退出");
            try { _e.Stop(); } catch { }
            if (_c.ManageSystemProxy) SysProxy.Restore(_snap);
            if (_icon != null) { _icon.Visible = false; _icon.Dispose(); }
            Application.Exit();
        }
    }

    // ===================== 入口 =====================
    public static class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {
            Cfg c = new Cfg();
            c.BaseDir = AppDomain.CurrentDomain.BaseDirectory;
            bool restoreOnly = false;

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (a == "--port" && i + 1 < args.Length) c.Port = int.Parse(args[++i]);
                else if (a == "--delay" && i + 1 < args.Length) c.Delay = int.Parse(args[++i]);
                else if (a == "--connect-timeout" && i + 1 < args.Length) c.ConnectTimeout = int.Parse(args[++i]);
                else if (a == "--probe-timeout" && i + 1 < args.Length) c.ProbeTimeout = int.Parse(args[++i]);
                else if (a == "--no-proxy") c.ManageSystemProxy = false;
                else if (a == "--reset-policy") c.ResetPolicy = true;
                else if (a == "--restore") restoreOnly = true;
            }

            Log.FilePath = c.LogFile;
            Log.W("==== 启动 ====");

            // 进程内有大量并发连接，每个连接会占用线程等待对端关闭
            ThreadPool.SetMinThreads(64, 64);

            if (restoreOnly)
            {
                SysProxy.BackupPath = c.BackupFile;
                SysProxy.Snapshot b = SysProxy.LoadBackup();
                if (b != null) { SysProxy.Restore(b); Console.WriteLine("[ok] system proxy restored from backup"); }
                else
                {
                    SysProxy.Snapshot off = new SysProxy.Snapshot();
                    off.Valid = true; off.Enable = 0;
                    SysProxy.Restore(off);
                    Console.WriteLine("[ok] no backup found, system proxy disabled");
                }
                return;
            }

            if (c.ResetPolicy)
            {
                try { if (File.Exists(c.PolicyFile)) File.Delete(c.PolicyFile); } catch { }
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new TrayApp(c));
        }
    }
}
