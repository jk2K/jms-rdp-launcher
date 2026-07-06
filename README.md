# jms-rdp-launcher

一个专门绕开 JumpServer Windows RDP 唤起参数问题的小启动器。

它接收浏览器传来的 `jms://base64(json)`，解析 JumpServer 的 RDP 信息，把 `.rdp`
文件写到用户配置目录。兼容 `file.name/file.content` 和 `filename/config` 两种
payload 结构；如果 `config` 自身还是 base64，程序会继续解码，并把 `\n` 转成真实
RDP 行分隔，然后用下面这种方式启动远程桌面：

如果检测到 JumpServer 形态的用户名（`username:s:user|token`），程序默认使用
`mac` profile：按 Swift/macOS 客户端的思路重新生成一份很短的 `.rdp` 配置，只保留
地址、用户名、显示、音频和 HiDPI 相关字段；同时把颜色深度固定为 32bpp，避免 Ubuntu
24.04 GNOME Remote Desktop / Wayland 场景在图形能力协商时被 24bpp 卡住。

模板的用法是：先在 Windows 的 MSTSC 里手动连接 Ubuntu 24.04 GNOME Remote Desktop，
确认能直连成功后，在 MSTSC 的“显示选项”里把这条连接“另存为”一个 `.rdp` 文件。
然后导入：

```powershell
E:\jms-rdp-launcher.exe --set-template C:\Users\root\Desktop\ubuntu-direct.rdp
```

之后从 JumpServer 点击 `jms://` 时，launcher 会保留这个成功模板里的大部分参数，
只替换：

```text
full address:s:<JumpServer RDP address>
username:s:<JumpServer username|token>
```

同时会丢弃模板里的 `password`、`gatewayaccesstoken` 等敏感字段。

## 凭据（关键）

JumpServer 的 razor RDP 网关按照 **用户名 = `user|token_id`、密码 = 连接令牌的
`token.value`（secret）** 来校验原生 RDP 登录。`.rdp` 文件里本身不含密码，secret
是通过 `jms://` payload 的 `token.value`（或顶层 `value`）单独下发的，官方客户端
再把它作为 RDP 密码喂给 mstsc。密码为空一定会被网关在登录阶段直接断开（现象：连上
`develop-jumpserver.jlcops.com:3389`、约 2~3 秒后 `Disconnect Reason = 2`）。

因此启动 mstsc 前，程序默认（`--use-cmdkey`，可用 `--no-cmdkey` 关闭）会从 payload
里解析 `token.value`，临时写入 Windows Credential Manager：目标 `TERMSRV/<jumpserver>`、
用户名 `user|token_id`、密码 `token.value`；事件日志监控结束后自动删除。

如果 payload 里 `token` 为空、也没有顶层 `value`（`"token": ""`），说明浏览器交过来的
`jms://` 链接根本不含 secret，任何启动器都无法通过网关认证。此时日志会打印
`token secret: absent ...` 和 `cmdkey install skipped: ... no token.value secret`，
需要先确认 JumpServer 侧真正下发了完整 payload（不要复用日志里被脱敏/截断的链接）。

可选 profile：

- `mac`：默认，贴近 Swift/macOS 客户端生成的短 RDP 配置，但使用 32bpp。
- `gnome`：保留 JumpServer 原始地址，显式开启 CredSSP/NLA、dynamic resolution，关闭 multitransport 和额外重定向。
- `template`：优先使用导入的 MSTSC 成功模板，没有模板时退回 `mac`。
- `swift`：贴近 Swift 客户端生成的短 RDP 配置，150% HiDPI、24bit、全屏。
- `legacy`：低带宽/低能力协商，保留 JumpServer 原始地址和 token 用户名。
- `raw`：不改 JumpServer 原始 `.rdp` 配置，只负责解析、落盘和启动 mstsc。

Windows 上默认使用 `ShellExecuteW(open, <name>.rdp)` 打开 `.rdp` 文件，也就是尽量
模拟双击 `.rdp` 文件，让系统文件关联去启动远程桌面。需要回退到直接启动
`mstsc.exe <name>.rdp` 时，可以传 `--direct-mstsc`。

## 构建

在 Windows VM 里：

```powershell
cargo build --release
```

生成文件：

```text
target\release\jms-rdp-launcher.exe
```

## 注册 jms:// 协议

先在 Windows VM 里运行一次：

```powershell
.\target\release\jms-rdp-launcher.exe --register
```

它会写入当前用户的注册表：

```text
HKCU\Software\Classes\jms\shell\open\command
```

之后从 JumpServer 页面点击“本地客户端 / 原生客户端 / RDP”时，浏览器会把 `jms://...`
交给这个程序处理。

## 调试

只解析，不启动 mstsc：

```powershell
.\target\release\jms-rdp-launcher.exe --inspect "jms://..."
```

只写出 `.rdp`，不启动 mstsc：

```powershell
.\target\release\jms-rdp-launcher.exe --write-only "jms://..."
```

指定 mstsc 路径：

```powershell
.\target\release\jms-rdp-launcher.exe --mstsc C:\Windows\System32\mstsc.exe "jms://..."
```

回退到直接启动 mstsc：

```powershell
.\target\release\jms-rdp-launcher.exe --direct-mstsc "jms://..."
```

清除已导入的 MSTSC 模板：

```powershell
E:\jms-rdp-launcher.exe --clear-template
```

切换参数 profile：

```powershell
.\target\release\jms-rdp-launcher.exe --profile swift "jms://..."
.\target\release\jms-rdp-launcher.exe --profile gnome "jms://..."
.\target\release\jms-rdp-launcher.exe --profile raw "jms://..."
```

如果要让浏览器唤起时固定使用某个 profile，可以重新注册：

```powershell
.\target\release\jms-rdp-launcher.exe --profile legacy --register
.\target\release\jms-rdp-launcher.exe --profile gnome --register
.\target\release\jms-rdp-launcher.exe --profile swift --register
.\target\release\jms-rdp-launcher.exe --profile raw --register
```

默认情况下，`mstsc.exe` 返回后程序还会继续等待 30 秒，并抓取 Windows RDP
客户端、RdpCoreTS、USB、Application 和 System 事件日志。可以调整等待时间：

```powershell
.\target\release\jms-rdp-launcher.exe --monitor-seconds 60 "jms://..."
```

关闭 cmdkey（改成让 mstsc 自己弹框输入密码，做对比实验时用）：

```powershell
.\target\release\jms-rdp-launcher.exe --no-cmdkey "jms://..."
```

日志默认写到：

```text
%APPDATA%\jms-rdp-launcher\launcher.log
```

日志里会记录原始参数、解析出的协议、写出的 `.rdp` 路径、mstsc 路径，以及客户端
退出码。
