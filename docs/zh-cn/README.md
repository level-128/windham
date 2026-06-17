# Windham

Windham 是一款自由的磁盘加密软件，基于 Linux 内核 dm-crypt 模块实现。它既具备 LUKS 的灵活性和功能完整性，又提供了 VeraCrypt 级别的可否认加密与隐蔽卷特性。无论注册多少口令，解锁时间始终恒定。

[English](/README.md) &nbsp;|&nbsp; [Français](/Document/README_fr.md)

> **预发布阶段。** 磁盘格式已经稳定但尚未正式冻结。请务必备份主密钥。

---

## 功能一览

- **透明块级加密** — 基于 dm-crypt，默认使用 aes-xts-plain64
- **可否认加密** — 磁盘上不存任何签名或魔数，所有字节都是加密随机数据。可选诱饵分区（隐藏卷）进一步隐藏加密数据的存在
- **最多 16 个密钥槽** — 支持密码、密钥文件、标准输入十六进制密钥、主密钥。槽数多少不影响解锁耗时
- **链接解锁级联** — 打开一个设备后，所有关联分区按优先级树自动逐级解锁。支持 `SHORTCUT` 标志在成功时剪掉同级其余分支
- **辅助数据区** — 与密钥绑定的加密元数据：纯文本备注、Shell 命令（解锁时执行）、链接解锁条目。会随加密头重变换而保留
- **探测** — 扫描块设备或文件，寻找 Windham 分区（支持 shebang / 魔数 / 悬置标记 / 熵检测四种方式），展示设备属性、UUID、挂载点
- **Unicode 口令输入** — Tab+空格键进入十六进制码位输入模式；密码统一规范化为 UTF-32BE 后再哈希，保证跨平台密钥派生结果一致
- **防篡改** — 悬置状态下对加密头的任何改动都会被检测到；内置多重完整性标记
- **自相关元数据** — 加密头重变换会改变绝大部分字节，模糊每次修改留下的痕迹，抵御槽历史攻击

---

## 十秒快速上手

```bash
# 构建
git clone https://github.com/level-128/windham.git --depth=1 && cd windham
cmake -B build && cmake --build build

# 创建 → 打开 → 格式化 → 关闭
sudo windham New   /dev/sdb                        # 新建加密设备
sudo windham Open  /dev/sdb                        # 解锁 → /dev/mapper/windham-<uuid>
sudo mkfs.ext4     /dev/mapper/windham-*           # 格式化文件系统
sudo mount         /dev/mapper/windham-* /mnt      # 挂载并使用
sudo windham Close windham-*                       # 锁定
```

---

## 文档

| 文档 | 内容 |
|---|---|
| [快速入门](docs/quickstart.md) | 分步指南（新建、打开、关闭、悬置、添加/删除密钥） |
| [安装与构建](docs/install.md) | 依赖、交叉编译、编译选项、ISO C 基础模式 |
| [安全模型](docs/security.md) | 主密钥体系、槽历史攻击、匿名密钥、侧信道防护、防篡改、密钥标识攻击 |
| [辅助数据区](docs/aux.md) | 三种条目类型（文本/Shell/链接）、实战场景（RAID 5/6、根分区级联） |
| [诱饵分区](docs/decoy.md) | GPT 布局原理、TRIM 问题、文件系统选择建议 |
| [启动时解锁](docs/windhamtab.md) | /etc/windhamtab 格式、Clevis+TPM2 集成、systemd 配合 |
| [PID 1 模式](docs/pid1.md) | 嵌入式/早期用户空间中作为 init 进程运行 |
| [参与贡献](docs/contribute.md) | 开发环境、测试套件、代码结构总览 |

每个操作的完整选项说明请运行 `windham Help <操作名>`（如 `windham Help Open`）。

---

## 支持的平台

| 层级 | 条件 | 能力 |
|---|---|---|
| **完整模式**（GNU/Linux） | Linux 2.6+、libdevmapper、libblkid、gettext、GNU 扩展 C11 编译器 | 全部功能可用 |
| **基础模式**（ISO C11） | stdlib.h、string.h、stdio.h、可选 threads.h、约 492 KB 堆内存 | 加密头管理、解锁、探测（无 dm-crypt 映射） |

完整模式的系统依赖：`libdevmapper-dev`、`linux-headers`、`libgettextpo-dev`、`libblkid-dev`、`libkeyutils-dev`。

---

## 许可证

GPL-3.0-or-later。© 2023–2025 level-128。  
第三方库的授权信息见 [library/license.md](/library/license.md)。
