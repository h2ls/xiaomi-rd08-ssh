using System.Net.Sockets;
using System.Text;
using Renci.SshNet;

namespace Rd08SshTool;

public interface IShell : IDisposable
{
    string Run(string cmd, int timeoutSec = 30);
}

internal sealed class SshShell : IShell
{
    private readonly SshClient _client;

    public SshShell(string ip, string user, string password)
    {
        var info = new ConnectionInfo(ip, user, new PasswordAuthenticationMethod(user, password))
        {
            Timeout = TimeSpan.FromSeconds(5),
        };
        _client = new SshClient(info);
        _client.Connect();
    }

    public string Run(string cmd, int timeoutSec = 30)
    {
        return _client.RunCommand(cmd).Result;
    }

    public void Dispose()
    {
        try
        {
            if (_client.IsConnected)
                _client.Disconnect();
        }
        catch
        {
        }
        _client.Dispose();
    }
}

// 应急通道: 重启后 dropbear 未启动时用 (nvram telnet_en=1)
internal sealed class TelnetShell : IShell
{
    private readonly TcpClient _client;
    private readonly NetworkStream _stream;

    public TelnetShell(string ip, string user, string password)
    {
        _client = new TcpClient();
        var connect = _client.ConnectAsync(ip, 23);
        if (!connect.Wait(TimeSpan.FromSeconds(5)))
        {
            _ = connect.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
            _client.Close();
            throw new TimeoutException($"连接 {ip}:23 超时");
        }
        connect.GetAwaiter().GetResult();

        _stream = _client.GetStream();
        _stream.ReadTimeout = 3000;

        ReadFor(2);
        Send(user + "\n");
        ReadFor(1);
        Send(password + "\n");
        var banner = Encoding.UTF8.GetString(ReadFor(2));
        if (banner.Contains("Login incorrect"))
        {
            _client.Close();
            throw new Exception("telnet 登录失败");
        }
    }

    public string Run(string cmd, int timeoutSec = 15)
    {
        Send(cmd + "; echo __D__\n");
        using var output = new MemoryStream();
        var end = DateTime.UtcNow.AddSeconds(timeoutSec);
        while (DateTime.UtcNow < end && !HasDoneMarker(output.ToArray(), cmd))
        {
            var chunk = ReadFor(1);
            output.Write(chunk, 0, chunk.Length);
        }
        return Encoding.UTF8.GetString(output.ToArray());
    }

    // 对齐 Python 的 out.split(cmd)[-1]: 去掉回显的命令本身之后, 末段出现 __D__ 即完成
    private static bool HasDoneMarker(byte[] output, string cmd)
    {
        var text = Encoding.UTF8.GetString(output);
        return text.Split(cmd, StringSplitOptions.None)[^1].Contains("__D__");
    }

    private byte[] ReadFor(double seconds)
    {
        using var ms = new MemoryStream();
        var end = DateTime.UtcNow.AddSeconds(seconds);
        var buf = new byte[4096];
        while (DateTime.UtcNow < end)
        {
            int n;
            try
            {
                n = _stream.Read(buf, 0, buf.Length);
            }
            catch (IOException e) when (e.InnerException is SocketException se &&
                                        se.SocketErrorCode is SocketError.TimedOut or SocketError.WouldBlock)
            {
                break;
            }
            if (n <= 0)
                break;
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }

    private void Send(string text)
    {
        var data = Encoding.UTF8.GetBytes(text);
        _stream.Write(data, 0, data.Length);
    }

    public void Dispose()
    {
        try
        {
            _client.Close();
        }
        catch
        {
        }
    }
}

public static class ShellFactory
{
    // 优先 SSH(root@ip)，失败回退 Telnet(root@ip)，重试 tries 次，全失败抛 Exception("SSH/Telnet 均无法登录: ...")
    public static IShell GetShell(string ip, string password, int tries = 1)
    {
        Exception? last = null;
        for (var i = 0; i < tries; i++)
        {
            try
            {
                return new SshShell(ip, "root", password);
            }
            catch (Exception e)
            {
                last = e;
            }
            try
            {
                return new TelnetShell(ip, "root", password);
            }
            catch (Exception e)
            {
                last = e;
            }
            Thread.Sleep(2000);
        }
        throw new Exception($"SSH/Telnet 均无法登录: {last?.Message ?? "None"}");
    }
}
