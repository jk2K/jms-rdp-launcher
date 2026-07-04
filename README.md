# jms-rdp-launcher

一个专门绕开 JumpServer Windows RDP 唤起参数问题的小启动器。

它接收浏览器传来的 `jms://base64(json)`，解析 JumpServer 的 RDP 信息，把 `.rdp`
文件写到用户配置目录，然后用下面这种方式启动远程桌面：

```powershell
mstsc.exe C:\Users\<you>\AppData\Roaming\jms-rdp-launcher\<name>.rdp
```

重点是 `.rdp` 文件路径作为独立参数传给 `mstsc.exe`，不会把整段参数拆空格，也不会把
文件路径额外塞进引号字符串里。

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

日志默认写到：

```text
%APPDATA%\jms-rdp-launcher\launcher.log
```

日志里会记录原始参数、解析出的协议、写出的 `.rdp` 路径，以及 `mstsc.exe` 的退出码。
