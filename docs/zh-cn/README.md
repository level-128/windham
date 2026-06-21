# Windham

Windham 是一款自由的磁盘加密软件，基于 Linux 内核 dm-crypt 模块实现自有规范。它兼具 LUKS 的功能性和 VeraCrypt 级别的可否认加密与隐蔽卷特性，在任意数量的口令注册下都能以恒定时间解锁。

[English](/README.md)

> **预发布阶段。** 磁盘格式稳定但尚未冻结。请务必备份主密钥。

---

## 功能一览

- **透明块级加密** — 支持 Linux dm-crypt 进行透明加密，搭配任意文件系统组合为加密卷。
- **可否认加密** — 加密随机的磁盘格式，无签名、无魔数，可选诱饵分区（隐写）
- **最多 16 个密钥槽** — 支持密码、密钥文件、主密钥。已注册密码数量不影响解锁耗时
- **链接解锁级联** — 打开一个设备，所有关联分区按可配置的优先级树自动逐级解锁。支持 `SHORTCUT` 标志剪掉同级分支，可实现容错 RAID 的存活路径发现
- **辅助数据区** — 与密钥绑定的加密元数据：纯文本备注、Shell 命令（解锁时执行）、链接解锁条目。会随加密头重变换而保留。
- **防篡改** — 任意时刻对加密头的修改会被检测到；内置多重完整性标记，即便是明文悬置状态下也无法篡改。
- **自相关元数据** — 加密头重变换改变大部分字节，模糊修改历史，抵御槽历史攻击。
- **可变密钥派生** — 使用内存困难密钥派生函数（Argon2id）搭配运行时可变参数密钥派生实现，大幅延缓攻击者使用专有电路进行暴力破解。

---

## 十秒快速上手

```bash
# 构建
git clone https://github.com/level-128/windham.git --depth=1 && cd windham
cmake -B build && cmake --build build
```

### 支持的平台

| 层级 | 条件 | 能力 |
|---|---|---|
| **完整模式**（GNU/Linux） | Linux 2.6+、libdevmapper、libblkid、gettext、GNU 扩展 C11 编译器 | 全部功能 |
| **基础模式**（ISO C11） | stdlib.h、string.h、stdio.h、可选 threads.h、约 510 KB 堆内存 | 加密头管理、解锁、探测（无 dm-crypt 映射） |

完整模式的系统依赖：`libdevmapper-dev`、`linux-headers`、`libgettextpo-dev`、`libblkid-dev`、`libkeyutils-dev`。参见[安装与构建](docs/install.md)。


```bash
# 创建：
sudo windham New   /dev/sdb                       # 新建加密设备
# 已有加密设备时：
sudo windham Probe                                # 列出 Windham 硬盘

# 解锁：
sudo windham Open  /dev/sdb --to=<设备名称>        # 解锁 → /dev/mapper/<设备名称>
# 如果未使用 --to 指定名称，将会使用 "windham-<UUID>" 作为设备名称
sudo mkfs.ext4     /dev/mapper/windham-*          # 格式化（这里用EXT4举例子）
sudo mount         /dev/mapper/windham-* /mnt     # 挂载并使用
```

```bash
sudo windham List                                 # 列出活跃映射

sudo windham Close <设备名称>                      # 锁定
# 或者
sudo windham Close --all                          # 锁定所有设备
```

---

## 文档

| 文档 | 内容 |
|---|---|
| [快速入门](docs/quickstart.md) | 分步指南（New、Open、Close、Suspend、AddKey、DelKey） |
| [安装与构建](docs/install.md) | 构建依赖、交叉编译、编译选项、ISO C 基础模式 |
| [安全模型](docs/security.md) | 主密钥体系、槽历史攻击、匿名密钥、侧信道、防篡改 |
| [辅助数据区](docs/aux.md) | Aux zone 类型（PLAINTEXT、SHELL、LINK_OPEN）、标志、RAID 级联 |
| [诱饵分区](docs/decoy.md) | 诱饵分区指南 — GPT 布局、TRIM 问题、文件系统建议 |
| [启动时解锁](docs/windhamtab.md) | /etc/windhamtab、Clevis + TPM2 集成、systemd init |
| [PID 1 模式](docs/pid1.md) | 以 PID 1 运行（嵌入式 / 早期用户空间） |
| [参与贡献](docs/contribute.md) | 开发环境、测试套件、代码结构 |
| [windham-raid-setup.sh](../scripts/windham-raid-setup.sh) | 一键 RAID 级联脚本（N 磁盘，冗余 SHORTCUT 链路） |

每个操作的完整选项说明请运行 `windham Help <操作名>`（如 `windham Help Open`）。

---

## 许可证

GPL-3.0-or-later。© 2023–2026 level-128。  
第三方库授权信息见 [library/license.md](/library/license.md)。
