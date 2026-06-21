# 以 PID 1 身份运行（嵌入式 / 早期用户空间）

在嵌入式 Linux 系统或极简 initramfs 环境中，没有独立的 init 守护进程时，Windham 可以直接作为 PID 1 启动。

> **不要在完整的 Linux 发行版上这样做。** 这只适用于嵌入式系统、没有 init 的 initramfs 或者极致精简的定制环境。

## 作为 PID 1 时会有什么不同

Windham 启动时检测到自己就是 PID 1，接下来的行为会完全改变：

1. 忽略所有命令行参数。
2. 从二进制文件内的 `.windhaminit` 区段获取二进制内的操作指令。
3. 执行该指令。
4. 如果成功，`exec` 到预设的后续程序（默认是 `/bin/sh`）。
5. 如果失败，内核 panic：`Kernel panic - not syncing - Attempted to kill init!`
   （如果预编译指令里包含了 `--nofail`，则跳过错误，直接 exec 后续程序）。

## 预编译指令的格式

编译时默认烧录的是 `windham Open TAB`，随后 `exec /bin/sh`。

你可以在编译好的二进制中用十六进制编辑器修改 `.windhaminit` 区段：

```
WINDHAMINIT:\xff<成功后的 exec 路径>\xff<操作名>\xff<参数>\xff<选项>...
```

- 各项之间用字节 `\xff` 分隔
- 每个字符串以 `\x00` 结尾
- 每项最多 255 个字符
- 运行日志会打印到内核 `dmesg`

```bash
# 查看 .windhaminit 区段
objdump -h windham | grep windhaminit

# $ objdump -h /bin/windham | grep windhaminit
 16 .windhaminit  00000100  00000000000416e0  00000000000416e0  000416e0  2**5
# 其中的 000416e0就是地址

# 用十六进制编辑器修改
hexedit /path/to/windham
# 回车 → 输入 0x416e0 → 回车 跳转到地址
# 按 TAB 在 ASCII 和16进制之间跳转
# 按 F2 保存，Ctrl+C 退出
```

```
000416E0   57 49 4E 44  48 41 4D 49  4E 49 54 3A  WINDHAMINIT:
000416EC   FF 2F 62 69  6E 2F 73 68  FF 4F 70 65  ./bin/sh.Ope
000416F8   6E FF 54 41  42 00 00 00  00 00 00 00  n.TAB.......
00041704   00 00 00 00  00 00 00 00  00 00 00 00  ............
00041710   00 00 00 00  00 00 00 00  00 00 00 00  ............
```



### 示例：单独解锁一块盘

```
WINDHAMINIT:\xff/bin/sh\xffOpen\xff/dev/sda\xff--key-file=/boot/key.bin\xff--nofail\x00
```

### 示例：按照 /etc/windhamtab 解锁后 exec 到 bash

```
WINDHAMINIT:\xff/bin/bash\xffOpen\xffTAB\xff--nofail\x00
```

## 内核命令行

在内核命令行中添加：

```
init=/path/to/windham
```

这样 Windham 就会成为 PID 1，执行预编译指令，然后 exec 到后续程序。

## 注意事项

- 早期用户空间没有终端（除非 systemd-ask-password 可用），所以**不能使用交互式密码输入**。只能用密钥文件（`--key-file`）或 Clevis。
- `dmesg` 是唯一的日志输出通道。
