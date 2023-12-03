# Windham

Windham 是一款免费且开源的磁盘加密软件，是其自身规范的实现，基于 Linux 的 dm-crypt 模块。

## 支持的功能：
- 透明且实时的磁盘（或分区）加密。
- 可抵赖加密：通过诱饵分区（隐写术）以及完全无签名且随机的加密头。
- 防篡改：修改加密头会使其无效。
- 密码管理：支持注册多个密码，可授权或不授权撤销。
- 原子性元数据：加密头的更改（例如添加新密钥）会导致其每个字节同时变化。

## 如何安装？
你可以选择：
- 下载适用于 X86_64 (Intel Haswell / AMD Bulldozer GEN4, 即 AMD Excavator Family 15h, 或更高版本) 的二进制文件（如果有的话）。
- 自己编译。需要 device-mapper 子系统。在基于 Debian 的发行版上安装 `libdevmapper`；在基于 Fedora 或 SUSE 的发行版上安装 `device-mapper`。在大多数发行版中应该已经可用。同时需要 `cmake`、`gettext-devel`
（Fedora/SUSE）/ `libgettextpo-dev`（基于 Debian）和 `gcc`。使用 cmake 编译 windham（`cmake CMakeLists.txt` -> `make` -> （可选）`sudo make install`）。

## 基本用法：
1. 首先，在 `/dev` 下找到你想加密的设备，可以使用磁盘管理器或命令 `lsblk`。它可能是 `/dev/sdb` 或 `/dev/nvme0n1`；如果你更愿意创建加密分区，可能是 `/dev/sdb2` 或 `/dev/nvme0n2p2`。
2. 要创建新的 Windham 设备，请使用命令 `windham New *your device*`。例如，在 `/dev/sdb` 上创建 Windham 设备，使用命令 `sudo windham New /dev/sdb` 并输入你的密码。
3. 要映射你的设备，请使用命令 `windham Open *your device* --to=*name*`。例如，要打开 `/dev/sdb`，使用 `sudo windham Open /dev/sdb --to=enc1` 会在 `/dev/mapper/enc1` 创建一个映射设备。
4. 在 `/dev/mapper/enc1` 上任意创建文件系统，就像它是一个空分区一样。
5. 要关闭你的设备，请使用 `windham close *name*`。
6. （可选，但推荐）使用 `windham Open *your device* --dry-run` 查看你的主密钥；将其备份到安全的地方。主密钥可以访问、控制和修改整个分区。

## 高级功能和示例：
- 挂起支持。使用 `windham Suspend` 来挂起加密设备。设备将可以被任何人访问。但是，放心，你的密码和主密钥是安全的，能够访问你的加密设备并不意味着别人可以阅读你的密码或破坏你设置的加密。
- 添加多达 6 个密码。你也可以通过 `windham RevokeKey` 撤销你的密码。使用被撤销的密码将触发错误（`此密钥已被撤销。`），而不是在密钥不正确时出现含糊的错误信息。即使你没有相应的密码，也可以通过 `windham RevokeKey --target-slot=*slot*` 撤销密码（这在你忘记密码时非常有用）。
- 使用 `windham Backup --to=*location*` 在处理分区时备份头。加密头的损坏将使加密设备无法访问。

**示例**：

命令 `New` 创建新的加密设备。在终端输入你的密钥，或使用 `--key --key-file` 之一。
你可以指定目标内存和时间使用。使用更多的时间或内存来增强对短密码的保护。
```
sudo Windham New /dev/nvme0n2p1
sudo Windham New /dev/nvme0n2 --target-time=0.8 
sudo Windham New /dev/nvme0n2 --key="hello world" --target-slot=2 --target-memory=1024000 --yes
sudo windham New /dev/sda --key-file=Documents/key --encrypt-type=twofish-xts-essiv --yes --target-time=2 --block-size=512 --decoy
```

命令 `Open` 用于打开设备。在终端提供你的密钥，或者使用 `--key` `--key-file` 或 `--master-key` 选项之一。`--allow-discards` 选项可以在使用 SSD 和 SMR 硬盘时提高性能。**但是，需要注意，在加密设备上允许块丢弃操作可能导致加
密设备的信息泄露（比如文件系统类型、已使用的空间等），尤其是如果以后能在设备上轻易找到被丢弃的块。** 此外，`--allow-discards` 选项可能不适用于 USB 闪存驱动器，因为操作系统可能无法通过 USB 传递 TRIM 命令。
```
sudo windham Open /dev/sda --to=crypt
sudo windham Open /dev/sdb --to=enc1 --master-key="9fab fe68 20e5 7b89 0b8e 2c01 b842 b268 136f 3d68 bc0c 0427 068a d687 6bf2 3348"
sudo windham Open /dev/sdb --to=c1 --allow-discards --no-read-workqueue --no-write-workqueue --unlock-slot=0 --systemd-dialog
sudo windham Open /dev/sdb --dry-run --verbose
```

`Close`: 关闭设备
```
sudo windham Close enc1
```

`AddKey`：添加一个新密钥。
`AddKey`、`RevokeKey`（只有在撤销密码时，不适用于撤销槽位）、`Backup`（除非使用 --no-transform 选项）和 `Suspend` 命令需要像 Open 命令一样的授权。你可以使用 Open 命令中相同的选项。
```
sudo windham AddKey /dev/nvme0n1
sudo windham AddKey /dev/nvme0n1 --unlock-slot=0 --target-slot=1`
```

`RevokeKey`:
```
sudo windham RevokeKey /dev/nvme0n1p4 
sudo windham RevokeKey /dev/nvme0n1p4 --target-slot=3
sudo windham RevokeKey /dev/nvme0n1p4 --obliterate
sudo windham RevokeKey /dev/nvme0n1p4 --unlock-slot=2 --key-file=file
```

用 `Backup` 备份加密头， `Restore` 来恢复:
```
sudo windham Backup /dev/sda --to=/home/level-128/header.bin 
sudo windham Restore /dev/sda --to=/home/level-128/header.bin 
```

`Suspend` （挂起）与 `Resume` （恢复）。打开挂起的加密设备会显示警告。 
```
sudo windham Suspend /dev/sdc --verbose
sudo windham Resume /dev/sdc
```


### Windham 如何工作的简介？
点击以下链接查看：
- [Windham 内存硬哈希函数的介绍](https://gitlab.com/level-128/argon2b3)
- [技术细节](/Document/technical_details.md)

## 诱饵分区简介
### 诱饵分区是什么？
诱饵分区是与加密的 Windham 分区位于同一区域的 FAT32 分区。加密分区占用 FAT32 分区的未使用扇区。在需要否认加密分区的存在时，可以使用诱饵分区。诱饵分区小于磁盘的全部空间。

### 如何启用诱饵分区？
使用 `windham New *your device* --decoy` 命令在创建加密分区的同时创建诱饵分区。要打开包含诱饵分区的加密分区，请像打开没有诱饵分区的分区一样操作。如果你已经删除了诱饵分区，自动检测将无法工作。在这种情况下，使用 `--decoy` 参数（除了 `New` 和 `Close`）强制程序识别给定设备拥有诱饵分区。

### 使用诱饵分区的注意事项
无法保证修改诱饵分区不会覆盖加密分区。在需要删除大量文件的情况下，重新格式化文件系统是一个更好的选择。

### 常见问题解答
点击以下链接查看常见问题解答：
- [常见问题及其解答](/Document/Q&A.md)

## 贡献
🥰🥰 欢迎来贡献 🥰🥰！
请确保你已经了解了[行为准则](CODE_OF_CONDUCT.md)。
有任何问题？请给我发邮件：level-128@gmx.com

## 许可证和法律问题
Copyright (C) 2023- W. Wang (level-128)

本程序是自由软件：您可以根据自由软件基金会发布的 GNU 通用公共许可证的条款，重新分发和/或修改它，版本为 3。
本程序的早期版本已授予根据第 7 条使用、传播和传递未经修改的被覆盖作品时适用的“附加许可”。从版本 0.231128 开始，“附加许可”已被撤销并移除。

### 美国加密出口法规
Windham 归类于 ECCN 5D002，提供或执行 EAR 第 772 部分定义的“非标准加密”，并受到工业和安全局出口管理法规的管辖。当源代码的加密功能更新或修改时，需要通过电子邮件通知 BIS 和 ENC 加密请求协调员其互联网位置（例如 URL 或互联网地址）。当做出贡献或分叉软件时，可以通过通知 level-128（电子邮件：<level-128@gmx.com>）来完成此操作。

我知道这个法规并不理想……
