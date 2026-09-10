using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Rd08SshTool;

Console.OutputEncoding = Encoding.UTF8;
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    Console.WriteLine("\n已取消");
    Environment.Exit(0);
};

const string Banner = """

==============================================================
 小米 BE6500 Pro (RD08 @ 1.1.96) SSH 工具
 漏洞: set_macfilter_rules name 参数注入 (认证后 RCE)
 声明: 月之暗面 K3 模型实现, 仅供学习研究, 勿用于未授权设备
==============================================================

""";

Console.WriteLine(Banner);
var ip = Ui.Ask("路由器 IP", "192.168.31.1");
if (!Ui.TcpOpen(ip, 80))
{
    Console.Error.WriteLine($"[!] 无法连接 {ip}, 请确认电脑与路由器在同一网络");
    Environment.Exit(1);
}

var webpw = Ui.Ask("路由器管理密码 (Web 后台密码)", secret: true);
var rootpw = Ui.Ask("要设置的 SSH root 密码", "admin");

var web = new RouterWeb(ip, webpw);
JsonDocument info;
try
{
    info = web.Login();
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[!] 登录失败: {ex.Message}");
    Environment.Exit(1);
    return;
}
using (info)
{
    var displayName = info.RootElement.TryGetProperty("displayName", out var dn) ? dn.ToString() : "?";
    var romversion = info.RootElement.TryGetProperty("romversion", out var rv) ? rv.ToString() : "?";
    Console.WriteLine($"\n[+] 登录成功: {displayName} / 固件 {romversion}");
}

while (true)
{
    var sshOn = Ui.TcpOpen(ip, 22);
    Console.WriteLine("\n---------------- 菜单 ----------------");
    Console.WriteLine($"  当前 SSH 状态: {(sshOn ? "已开启" : "未开启")}");
    Console.WriteLine("  1 - 开启 SSH (漏洞利用, 重启后失效)");
    Console.WriteLine("  2 - 固化 SSH (软固化: 开机自启脚本, 需 SSH 已开启)");
    Console.WriteLine("  3 - 深度固化 (bdata/crash 分区, 三次重启, 抗固件升级)");
    Console.WriteLine("  0 - 退出");
    var choice = Ui.Ask("请选择", sshOn ? "0" : "1");

    if (choice == "0")
    {
        break;
    }
    else if (choice == "1")
    {
        Console.WriteLine("\n[!] 即将对路由器执行命令注入以开启 SSH (root 权限)。");
        Console.WriteLine("    该操作不修改任何分区, 重启后失效, 但理论上存在极小风险。");
        if (!Ui.Confirm("确认要开启 SSH 吗?")) continue;
        if (Features.EnableSsh(web, rootpw))
            Console.WriteLine($"\n[+] SSH 已开启: ssh root@{ip}  密码: {rootpw}");
        else
            Console.WriteLine("\n[-] SSH 端口未开放, 注入可能已被修复");
    }
    else if (choice == "2")
    {
        Console.WriteLine("\n[!] 软固化: 在 /data/auto_ssh 安装开机自启脚本 (uci firewall include)。");
        Console.WriteLine("    不碰系统分区, 可用 uci delete firewall.auto_ssh 卸载, 安全可逆。");
        if (!Ui.Confirm("确认进行软固化?")) continue;
        try
        {
            if (Features.SoftPersist(ip, rootpw))
                Console.WriteLine("[+] 软固化完成, 重启后 SSH 将自动开启");
            else
                Console.WriteLine("[-] 校验失败, 请手动检查");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] 失败: {ex.Message}");
        }
    }
    else if (choice == "3")
    {
        Console.WriteLine("\n[!!] 深度固化会写入 bdata/crash 分区并三次重启路由器!");
        Console.WriteLine("     建议先备份全部分区 (xmir-patcher 菜单 4)。出错可用");
        Console.WriteLine("     小米官方修复工具 + 备份恢复。");
        if (!Ui.Confirm("我已了解风险并已完成备份, 确认继续?")) continue;
        try
        {
            if (Features.DeepPersist(ip, rootpw))
                Console.WriteLine("[+] 深度固化完成! 固件升级/恢复出厂后 SSH/telnet 仍可恢复");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] 中断: {ex.Message}");
        }
    }
    else
    {
        Console.WriteLine("无效选择");
    }
}

Console.WriteLine("再见。");

namespace Rd08SshTool
{
    public static class Ui
    {
        public static string Ask(string prompt, string? def = null, bool secret = false)
        {
            Console.Write(def is not null ? $"{prompt} [{def}]: " : $"{prompt}: ");
            var v = secret && !Console.IsInputRedirected
                ? ReadSecret()
                : Console.ReadLine() ?? Cancel();
            v = v.Trim();
            return v.Length > 0 ? v : def ?? "";
        }

        public static bool Confirm(string prompt, bool def = false)
        {
            var v = Ask($"{prompt} (y/n)", def ? "y" : "n").ToLowerInvariant();
            return v is "y" or "yes" or "是";
        }

        public static bool TcpOpen(string ip, int port, int timeoutMs = 2000)
        {
            try
            {
                using var client = new TcpClient();
                client.ConnectAsync(ip, port)
                    .WaitAsync(TimeSpan.FromMilliseconds(timeoutMs))
                    .GetAwaiter().GetResult();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string ReadSecret()
        {
            var sb = new StringBuilder();
            while (true)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    return sb.ToString();
                }
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0)
                        sb.Length--;
                    continue;
                }
                if (!char.IsControl(key.KeyChar))
                {
                    sb.Append(key.KeyChar);
                }
            }
        }

        private static string Cancel()
        {
            Console.WriteLine("\n已取消");
            Environment.Exit(0);
            return "";
        }
    }
}
