# 备份与恢复

每个 Windham 加密头里都包含主密钥、全部 16 个口令槽、密钥池和辅助数据区密钥。
加密头丢失就意味着数据丢失——请务必备份。Windham 提供三种备份模式以及配套的恢复流程。

## 备份模式

### 完整加密头备份（默认）

```bash
sudo windham Backup /dev/sdb --to=windham_backup
```

- 导出**原始加密头**（约 20 KB），包含**全部**已注册的口令槽。
- 需要设备和一个有效密钥（`--key`、`--key-file`、`--master-key`）。
- 拒绝覆盖已存在的文件——确实需要覆盖时请先手动删除旧备份。
- 用 `Restore --to` 恢复。

### 折叠备份（`--fold`）

```bash
sudo windham Backup --fold --to=sdb_fold.bin /dev/sdb --key=123
```

- 解锁设备后只导出**与给定密钥匹配的单个密钥槽**：一个 `Key_slot`（144 B）
  加上 UUID、盐和元数据，共约 960 字节。
- 其余密钥槽全部清零，元数据用主密钥重新加密——备份文件是密文，不会泄露
  额外信息。
- 专为纸质恢复、二维码编码或"只离线保存一个密钥、不暴露其他密钥"设计。
- 恢复时需要创建备份时使用的同一口令（或主密钥）。

### 二维码备份（`--qrcode`）

```bash
# 从设备实时编码：在终端打印二维码
sudo windham Backup --qrcode /dev/sdb --key=123

# 保存为 1-bit BMP 图片而不是终端输出
sudo windham Backup --qrcode=sdb_qr.bmp /dev/sdb --key=123

# 离线：直接编码已有的折叠备份文件——无需设备
sudo windham Backup --qrcode --to=sdb_fold.bin
```

- 把同样的折叠数据编码成二维码（自动选择最小版本，ECC 中等）。
- 终端输出使用 Unicode 方块字符，需要支持 Unicode 的终端；否则请用 BMP 变体。
- `--qrcode` 既没有 `--to` 也没有设备时没有数据来源，会报错。

## 恢复

```bash
# 完整加密头备份
sudo windham Restore /dev/sdb --to=windham_backup

# 折叠备份（需要备份时使用的口令 / 主密钥）
sudo windham Restore --fold /dev/sdb --to=sdb_fold.bin --key=123
```

**永远不要克隆 Windham 设备。** 恢复始终保留备份中记录的原始扇区范围——
恢复到不同大小的设备会被拒绝。两台设备共享同一个加密头就意味着共享同一个
主密钥，这是灾难性的安全风险。

## 安全注意事项

- 备份请离线保存（纸、二维码打印件或断开网络的介质）。备份和设备同时落入
  他人之手，等于磁盘被窃。
- `Destroy` 之后请一并删除你的备份——如果加密头将来被重建，备份中的主密钥
  仍能打开数据。
- 对诱饵分区（decoy partition）做备份/恢复时使用 `--decoy` 标志
  （`Backup --decoy`、`Restore --decoy`）。
