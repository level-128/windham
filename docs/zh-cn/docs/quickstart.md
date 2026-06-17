# 快速入门指南

## 1. 找到目标设备

用 `lsblk` 或 `fdisk -l` 找到块设备路径，例如 `/dev/sdb`、`/dev/nvme0n1p3`。
**该设备上的数据将被覆盖。**

## 2. 创建加密分区

```bash
sudo windham New /dev/sdb --key="你的密码"
```

这会在设备头部写入加密头并注册第一条口令。默认使用 `aes-xts-plain64` 加密算法，扇区大小 4096 字节。

影响口令强度的几个选项（对弱密码尤其重要）：

- `--target-time=<秒数>`  — KDF 运算时长（默认 1.5 秒，越大越安全）
- `--target-memory=<KiB>` — KDF 使用的最大内存量
- `--target-level=<级别>` — KDF 的最大迭代级别

## 3. 解锁并建立映射

```bash
sudo windham Open /dev/sdb --key="你的密码"
# 映射为 /dev/mapper/windham-<uuid>

# 如果希望起一个简短的名字：
sudo windham Open /dev/sdb --key="你的密码" --to=mycrypt
# 映射为 /dev/mapper/mycrypt
```

## 4. 创建文件系统

```bash
sudo mkfs.ext4 /dev/mapper/mycrypt
```

## 5. 挂载使用

```bash
sudo mount /dev/mapper/mycrypt /mnt
# ……进行文件读写……
sudo umount /mnt
```

## 6. 关闭（重新上锁）

```bash
sudo windham Close mycrypt
```

## 7. 备份主密钥

```bash
sudo windham Open /dev/sdb --key="你的密码" --dry-run
# 终端会打印主密钥的十六进制形式——务必离线、安全地保存！
```

**主密钥可以解锁、读写、修改整个加密分区。一旦丢失或泄露，无法重新生成。** 请把它离线保存在纸上、U 盘或硬件安全模块里。

---

## 管理密钥

### 添加新口令

```bash
sudo windham AddKey /dev/sdb --key="旧密码" --target-time=2
# 终端会提示输入新密码
```

不加 `--rapid-add` 时会执行完整的加密头重变换（安全，但已有多个密钥时会很慢）。如果你的威胁模型里不存在槽历史攻击，可以用 `--rapid-add` 大幅加速。

### 删除某条口令

```bash
sudo windham DelKey /dev/sdb --key="要删除的口令"
```

### 查看已注册的密钥

```bash
sudo windham Open /dev/sdb --key="任意有效口令" --dry-run
# 会列出全部 16 个槽的占用情况
```

---

## 悬置与恢复

悬置（Suspend）会把中间密钥写入加密头，此后可以免密打开：

```bash
sudo windham Suspend /dev/sdb --key="你的密码"
# 悬置后可以无密码打开
sudo windham Open /dev/sdb
# ...
sudo windham Close windham-*
sudo windham Resume /dev/sdb --key="你的密码"
# 恢复后重新要求口令
```

---

## 探测——寻找 Windham 设备

```bash
# 扫描系统中所有块设备
sudo windham Probe

# 仅探测某个设备
sudo windham Probe --dir=/dev/sdb

# 探测某个目录下的全部文件
sudo windham Probe --dir=/mnt/headers/
```

---

## 备份与恢复加密头

```bash
sudo windham Backup /dev/sdb --to=加密头备份文件
sudo windham Restore /dev/sdb --to=加密头备份文件
```

---

## 接下来可以

- 运行 `windham Help <操作名>` 查看完整选项
- 设置[链接解锁级联](aux.md)实现多设备联动打开
- 配置 [/etc/windhamtab](windhamtab.md) 实现开机自动解锁
- 阅读[安全文档](security.md)深入了解 Windham 的密钥体系与攻击防御
