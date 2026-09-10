using System.Text;

namespace Rd08SshTool;

public static class Features
{
    // ---------------------------------------------------------------- 功能 1: 开启临时 SSH

    public static bool EnableSsh(RouterWeb web, string rootpw)
    {
        int b = Random.Shared.Next(0x10, 0xD1);
        var macs = new string[3];
        for (int i = 0; i < 3; i++)
            macs[i] = $"0A:11:22:33:44:{b + i:X2}";

        var steps = new (string Desc, string Cmd)[]
        {
            ("写入 nvram ssh_en=1", "nvram set ssh_en=1 && nvram set telnet_en=1 && nvram commit"),
            ("修改 dropbear 并启动", "sed -i \"s/channel=.*/channel=\\\"debug\\\"/g\" /etc/init.d/dropbear && /etc/init.d/dropbear start"),
            ($"设置 root 密码为 {rootpw}", $"echo -e \"{rootpw}\\n{rootpw}\" | passwd root"),
        };

        try
        {
            for (int i = 0; i < steps.Length; i++)
            {
                Console.WriteLine($"  [{i + 1}/3] {steps[i].Desc} ...");
                if (!web.Rce(macs[i], steps[i].Cmd))
                {
                    Console.WriteLine("  注入请求被拒绝, 可能固件已修复");
                    return false;
                }
            }
            Thread.Sleep(2000);
            return Ui.TcpOpen(web.Ip, 22);
        }
        finally
        {
            foreach (var m in macs)
                web.MacfilterDel(m);
        }
    }

    // ---------------------------------------------------------------- 功能 2: 软固化 (开机自启)

    private const string AutoSsh =
        "#!/bin/sh\n" +
        "# auto_ssh: 每次开机重新放开 dropbear (nvram ssh_en 已持久, 只需修 channel)\n" +
        "sleep 5\n" +
        "sed -i 's/channel=.*/channel=\"debug\"/g' /etc/init.d/dropbear\n" +
        "/etc/init.d/dropbear restart\n";

    // 通过已有 shell 安装 auto_ssh 开机自启 (base64 传输避免引号问题)
    private static void InstallAutoSsh(IShell sh)
    {
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(AutoSsh));
        var cmds = new[]
        {
            "mkdir -p /data/auto_ssh",
            $"echo {b64} | base64 -d > /data/auto_ssh/auto_ssh.sh",
            "chmod +x /data/auto_ssh/auto_ssh.sh",
            "uci set firewall.auto_ssh=include",
            "uci set firewall.auto_ssh.type='script'",
            "uci set firewall.auto_ssh.path='/data/auto_ssh/auto_ssh.sh'",
            "uci set firewall.auto_ssh.enabled='1'",
            "uci commit firewall",
        };
        foreach (var c in cmds)
            sh.Run(c);
    }

    public static bool SoftPersist(string ip, string rootpw)
    {
        var sh = ShellFactory.GetShell(ip, rootpw);
        try
        {
            InstallAutoSsh(sh);
            var output = sh.Run("uci get firewall.auto_ssh.path");
            return output.Contains("auto_ssh.sh");
        }
        finally
        {
            sh.Dispose();
        }
    }

    // ---------------------------------------------------------------- 功能 3: 深度固化 (bdata/crash, 三次重启)

    private static bool WaitRouterDown(string ip)
    {
        Console.WriteLine("  等待路由器重启 ...");
        Thread.Sleep(5000);
        for (int i = 0; i < 12; i++)  // 最多等 ~60s 让端口先关掉
        {
            if (!Ui.TcpOpen(ip, 22) && !Ui.TcpOpen(ip, 80))
                return true;
            Thread.Sleep(5000);
        }
        return false;
    }

    private static IShell WaitRouterUp(string ip, string rootpw, int timeoutSec = 420)
    {
        Console.WriteLine("  等待路由器上线 ...");
        var end = DateTime.Now.AddSeconds(timeoutSec);
        while (DateTime.Now < end)
        {
            if (Ui.TcpOpen(ip, 80))
            {
                try
                {
                    return ShellFactory.GetShell(ip, rootpw);
                }
                catch (Exception)
                {
                }
            }
            Thread.Sleep(6000);
        }
        throw new Exception("等待超时, 路由器未恢复。请手动检查路由器状态后再继续。");
    }

    public static bool DeepPersist(string ip, string rootpw)
    {
        Console.WriteLine("\n  [深度固化步骤说明]\n" +
            "  第 1 步: 向 crash 分区写入 magic, 使 bootloader 进入调试引导 -> 自动重启\n" +
            "  第 2 步: 将 ssh_en/telnet_en/uart_en/boot_wait 写入 bdata (抗恢复出厂) -> 自动重启\n" +
            "  第 3 步: 擦除 crash 分区, 恢复正常引导 -> 自动重启, 固化完成\n");
        if (!Ui.Confirm("  准备就绪, 开始第 1 步?"))
            return false;

        var sh = ShellFactory.GetShell(ip, rootpw);
        sh.Run(@"zz=$(dd if=/dev/zero bs=1 count=2 2>/dev/null) ; printf '\xA5\x5A%c%c' $zz $zz | mtd write - crash");
        sh.Run("reboot");
        sh.Dispose();
        WaitRouterDown(ip);
        sh = WaitRouterUp(ip, rootpw);

        Console.WriteLine("  [第 2 步] 写入 bdata ...");
        sh.Run("nvram set ssh_en=1 && nvram set telnet_en=1 && nvram set uart_en=1 && nvram set boot_wait=on && nvram commit");
        sh.Run("bdata set ssh_en=1 && bdata set telnet_en=1 && bdata set uart_en=1 && bdata set boot_wait=on && bdata commit");
        sh.Run("reboot");
        sh.Dispose();
        WaitRouterDown(ip);
        sh = WaitRouterUp(ip, rootpw);

        Console.WriteLine("  [第 3 步] 擦除 crash ...");
        sh.Run("mtd erase crash");
        sh.Run("reboot");
        sh.Dispose();
        WaitRouterDown(ip);
        sh = WaitRouterUp(ip, rootpw);

        // 调试引导循环会清空 /data 和 overlay 配置, 需重新开启 dropbear 并重装 auto_ssh
        Console.WriteLine("  [收尾] 恢复 dropbear 并重装 auto_ssh 自启 ...");
        sh.Run("sed -i 's/channel=.*/channel=\"debug\"/g' /etc/init.d/dropbear && /etc/init.d/dropbear start");
        InstallAutoSsh(sh);
        sh.Dispose();
        return true;
    }
}
