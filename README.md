# jms-rdp-launcher

一个把 JumpServer `jms://` 链接解析成 `.rdp` 文件、并唤起原生 RDP 客户端的小启动器。
**同时支持 macOS 和 Windows 两个操作系统**，同一份二进制会自动识别当前系统，选用各自
原生的 RDP 客户端来打开远程桌面：

- **macOS** → 通过 `open` 唤起系统里的 **"Windows App"**（原 Microsoft Remote Desktop）
  来连接远程桌面。需要先从 Mac App Store 安装 Windows App。
- **Windows** → 通过系统自带的 **`mstsc.exe`**（远程桌面连接）来连接远程桌面（默认用
  `ShellExecute` 打开 `.rdp` 模拟双击；可用 `--direct-mstsc` 改成直接启动 `mstsc.exe`）。

它接收浏览器传来的 `jms://base64(json)`，解析 JumpServer 的 RDP 信息，生成一份
`.rdp` 文件写到用户配置目录，然后按上面的方式按系统唤起客户端。

兼容 `file.name/file.content` 和 `filename/config` 两种 payload 结构；如果 `config`
本身还是 base64，程序会继续解码，并把 `\n` 转成真实 RDP 行分隔。

**只有一种 RDP profile。** 当 payload 里的用户名是 JumpServer token 形态
（`user|token_id`）时，启动器会用网关地址 + token 用户名重新生成一份精简配置
（见下文「为什么是这份配置」）；普通 `.rdp`（不含 token 用户名，例如 `--rdp-file`
直接启动已保存的文件）则原样落盘、原样启动。

## 为什么是这份配置（重要，踩过的坑）

重新生成的 `.rdp` **刻意只保留地址、用户名、显示和性能字段**，对照的是官方
JumpServer macOS 客户端（Swift）默认的 `balanced` 质量配置。两个关键点都是实测得来的：

1. **`session bpp:i:24`，不是 32。** 用 32bpp 时，Microsoft Windows App 会去协商
   AVC444 / H.264 图形编解码；Ubuntu 24.04 的 GNOME Remote Desktop 给不了，于是
   `PopulateCodecCapabilities()` 失败、会话被断（日志里能看到 `No data of type
   0xc08/0xc09`）。24bpp 走不到那条编解码路径，能正常连上。（早期文档里写过"固定
   32bpp 避免 Ubuntu 24.04 协商卡住"，方向反了 —— 真正能连的是 24bpp。）

2. **不写 `prompt for credentials on client`、`authentication level`、
   `enablecredsspsupport`、以及任何 gateway 字段。** 写了 `prompt for credentials on
   client:i:0` 会让客户端**不弹密码框**，而 `.rdp` 又不含密码，结果网关拿不到凭据直接
   断开（`Disconnect Reason = 2`，现象就是"马上断开"）；写 `authentication level:i:2`
   会因为网关证书不受信而拒绝连接。把它们都省掉，让客户端走默认行为（弹框问密码、
   接受网关），连接才过得去。

生成的配置长这样（1920×1080 逻辑分辨率 × HiDPI 1.5 = 2880×1620）：

```text
full address:s:<网关地址>
username:s:<user|token_id>
desktopwidth:i:2880
desktopheight:i:1620
session bpp:i:24
forcehidpioptimizations:i:1
desktopscalefactor:i:150
hidef color depth:i:24
compression:i:1
font smoothing:i:1
disable wallpaper:i:0
disable menu anims:i:1
disable themes:i:0
audiomode:i:0
smart sizing:i:1
screen mode id:i:2
```

## 凭据（密码）

JumpServer 的 `.rdp` 本身不含密码。对 RDP 原生客户端来说，密码由客户端**弹框向用户
索取**（官方 Swift 客户端也是这么做的，它同样不把 token 当 RDP 密码）：

- **macOS**：Windows App 打开 `.rdp` 后会弹凭据框，用户输入**资产账号密码**即可。
  `.rdp` 没法内嵌可用明文密码，所以这里靠弹框。
- **Windows**：默认（`--use-cmdkey`，可用 `--no-cmdkey` 关闭）会尝试把 payload 里的
  `token.value`（如果非空）写进 Credential Manager 给 mstsc 用；但当前这台
  JumpServer 下发的 `token` 是空字符串，所以 cmdkey 实际会被跳过，mstsc 同样弹框问
  密码。

如果某次 payload 里 `token` 非空、也没有顶层 `value`，日志会打印
`token secret: absent ...` 和相应的 `cmdkey install skipped / macOS clipboard handoff
skipped`，说明这次链接本身不含 secret，靠弹框输密码即可，不算错误。


**踩过的坑，如果 jumpserver 连接窗口那配置的用户名和密码是错误的，远程桌面连接会立马断开不会给账户和密码错误的提示**

## 构建

```bash
cargo build --release
```

产物：

- Linux/macOS：`target/release/jms-rdp-launcher`
- Windows：`target\release\jms-rdp-launcher.exe`

## 注册 jms:// 协议

### Windows

```powershell
.\target\release\jms-rdp-launcher.exe --register
```

写入当前用户的注册表 `HKCU\Software\Classes\jms\shell\open\command`。之后从 JumpServer
页面点击「本地客户端 / 原生客户端 / RDP」时，浏览器会把 `jms://...` 交给这个程序。

### macOS（原生安装：AppleScript applet + .dmg）

macOS 把 `jms://` 通过 **GURL Apple Event** 交给处理器，**不是 argv**，所以纯命令行
二进制（即使放进 `.app`）收不到 URL。方案是用一个 **AppleScript applet** 当 `.app`
的壳：它的 `on open location` 能可靠地收到 URL，再用 `do shell script` 把 URL 作为
argv 喂给本 Rust 二进制。applet 直接打开时（双击）跑 `on run`，调用二进制的
`--register-self` 把自己注册成 `jms://` 默认处理器，**用户全程不用碰 lsregister / plist**。

一条命令构建 `.app` + 拖拽安装的 `.dmg`：

```bash
./scripts/build-macos.sh
# 产物：dist/JMSRdpLauncher.app  和  dist/JMSRdpLauncher.dmg
```

安装：打开 `dist/JMSRdpLauncher.dmg` → 把 `JMSRdpLauncher` 拖到 `Applications` →
双击打开一次（弹"已安装"对话框，同时完成 `jms://` 自注册）。之后从 JumpServer 点
`jms://` 链接就会���起它。

实现要点（都已踩过坑）：

- **applet 的 `CFBundleIdentifier` 必须显式设成 `local.jms-rdp-launcher`**（`osacompile`
  不生成它），并和 LaunchServices 的默认 handler 一致 —— 否则 `jms://` 路由不稳。
- **改过 bundle 内容后必须重新 `codesign --force --deep --sign -`**，否则 LaunchServices
  静默拒绝把它当 URL handler。
- 如果系统里**别的程序也抢占了 `jms:`**（比如 IntelliJ、或官方
  `com.jumpserver.protocol-handler`），LaunchServices 路由会变不稳。`--register-self`
  已经用 `LSSetDefaultHandlerForURLScheme` 把默认指过来，但若仍偶发路由到别的 app，
  去那个 app 里取消它的 `jms:` 注册，或 `lsregister -kill -r` 重建一下 LS 库。

> 备注：之所以用 applet 而不是"纯 Rust 二进��直接用 NSApplication 收 GURL"——后者代码
> 写过也跑通了（`application:openURLs:` + `NSAppleEventManager` 两条路都试了），但在
> ad-hoc 签名下 LaunchServices 投递 URL 极不稳（实测 ~20–40%）。applet 的
> `on open location` 实测 5/5 稳定。要真正纯原生 + 稳，需要 Apple Developer ID 正式签名
> + 公证。

不注册也能调试：直接 `./jms-rdp-launcher "jms://..."`。

## 调试

```bash
./jms-rdp-launcher --inspect "jms://..."     # 只解析、打印预览，不启动客户端
./jms-rdp-launcher --write-only "jms://..."  # 只写出 .rdp，不启动客户端
./jms-rdp-launcher --mstsc /path/to/client "jms://..."   # 覆盖客户端
./jms-rdp-launcher --rdp-file path/to/file.rdp          # 直接启动已有 .rdp
```

日志默认写到：

- Windows：`%APPDATA%\jms-rdp-launcher\launcher.log`
- macOS/Linux：`~/.config/jms-rdp-launcher/launcher.log`

日志里会额外记录两份 `.rdp` 内容：**重新生成后**的（`rdp file content redacted`）和
**JumpServer 原始的**（`ORIGINAL jumpserver rdp content redacted`），方便对照排查。
另外 `payload summary` 一行会列出 payload 的顶层字段结构（只看 key/类型，不泄露
secret）。完整原始 `jms://` 会写到同目录 `last_jms_url.txt`，便于回放。

## 调试选项一览

```text
--inspect            解析并打印预览，不启动客户端
--write-only         解析并写出 .rdp，不启动客户端
--mstsc <path>       覆盖 RDP 客户端
--log <path>         覆盖日志路径
--rdp-file <path>    直接启动一个已存在的 .rdp
--no-wait            启动客户端后立即返回
--direct-mstsc       仅 Windows：直接启动 mstsc.exe 而不是 ShellExecute .rdp
--use-cmdkey         仅 Windows：把 user|token_id + token.value 写进凭据管理器（默认）
--no-cmdkey          不注入凭据
--monitor-seconds N  仅 Windows：mstsc 返回后等待 N 秒并抓取 RDP 事件（默认 30）
--register           把本程序注册为当前用户的 jms:// 处理器
--unregister         移除当前用户的 jms:// 注册
```
