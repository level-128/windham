# 辅助数据区

每个 Windham 分区都有一个可选的**辅助数据区**——紧跟在加密头后面的一小块区域（默认 8 KiB），用于保存与密钥绑定的元数据。每个条目独立加密，密钥从负责解锁该设备的密钥槽派生而出。

## 设计要点

- **位置**：设备起始扇区后第 `start_aux_sector` 个扇区（默认为加密头末端，第 40 扇区）
- **大小**：可通过 `--aux-sector-size` 自行指定（默认 16 扇区 = 8 KiB）
- **加密方式**：每个条目有自己独立的随机初始向量，用 AES-CBC 加密。密钥来自解锁所用密钥槽的口令哈希值。
- **公开条目**：若使用主密钥解锁，辅助数据区的槽密钥变为全零（不加密），这类公开条目即使没有正常口令也能被 `--aux-probe` 列出。
- **跨重变换保留**：在正常（非 rapid）加密头重变换中，辅助数据区会用新的 CBC 初始向量重新加密，因此里面的数据会随加密头一起"跟随"，不会丢失。
- **随密钥自动清理**：当某条口令被删除（`DelKey`）时，所有以该口令加密的辅助数据条目会被一并移除。

## 条目类型

### 纯文本条目（PLAINTEXT）

直接存放原始 char32_t 内容。通过 `--aux-add=<内容>` 添加。

```bash
windham Aux /dev/sda --key=我的密码 --aux-add="备份口令提示词：蓝色大象"
```

### Shell 命令条目（SHELL）

在设备打开时执行的一段 Shell 命令。通过 `--aux-add-command=<命令>` 添加。

**内部结构**：类型标记、标志位、超时秒数、命令长度、命令字符串（char32_t）。

**标志位**：
- `BLCKOPEN`——若命令执行失败，则阻止本次 Open 操作。这是 `--add-command` 的默认行为。

```bash
# 解锁后自动组装 RAID，组装失败则阻断打开
windham Aux /dev/sda --key=我的密码 \
    --aux-add-command="mdadm --assemble /dev/md0 /dev/mapper/windham-*" \
    --aux-flag=BLCKOPEN
```

### 链接解锁条目（LINK_OPEN）

指向另一个 Windham 分区的引用。当父设备被打开时，关联设备会自动加入解锁队列，逐级级联解锁。通过 `--aux-add-link=<目标路径>` 添加。

**内部结构**：类型标记、标志位、目标所需的 KDF 级别、优先级、目标 UUID、预哈希的口令（char32_t）。

**标志位**：
- `SHORTCUT`——若该链接解锁成功，则跳过同一层级中剩余的所有兄弟链接。

**优先级**：`--aux-link-prio=<0-255>`（默认 128），数值越低越优先处理。同一个设备的辅助数据区中，所有 LINK_OPEN 条目按优先级排序，优先级最低的条目最先被打开。

**目标设备的口令**：用 `--aux-target-key=<密码>` 或 `--aux-target-keyfile=<文件路径>` 提供。若两者都未给出，会弹出交互式提示。

```bash
# 将 /dev/sdb 链接到 /dev/sda：打开 sda 时 sdb 会自动解锁
windham Aux /dev/sda --key=我的密码 \
    --aux-add-link=/dev/sdb --aux-target-key=另一个密码 --aux-link-prio=100
```

#### 级联行为详解

对一个含有 LINK_OPEN 条目的设备执行 `Open` 时：

1. 父设备先解锁并建立映射。
2. 读取并解密其辅助数据区，扫描所有 LINK_OPEN 条目。
3. 每个条目按优先级降序排列，然后以"当前深度 + 1"推入 FIFO 处理队列。
4. 队列依次处理每一个关联设备，而每个关联设备被打开后又可能再贡献出**自己的** LINK_OPEN 条目，形成更深层的递归级联。
5. 若某条链接带有 `SHORTCUT` 标志且成功打开，同一深度上剩余的所有条目会被直接丢弃（修剪级联树）。
6. 已打开过的设备通过 UUID 去重，不会重复解锁，因此不会产生闭环。
7. 可通过 `--aux-link=/dev/sdX,/dev/sdY` 将 UUID→设备路径的解析限制在指定设备范围内，避免扫描整个 `/proc/partitions`。

```
示例拓扑：
  A → B(优先级=50, SHORTCUT), C(优先级=100)
  B → D, E

  打开 A 时：
    1. A 的链接排序：[C(100), B(50)]
    2. B 最先打开 → SHORTCUT 生效 → C 被剪掉
    3. D、E 随即打开
  最终结果：A、B、D、E 成功打开；C 被跳过
```

## 实战场景

### RAID 5/6 部署

对于需要在个别磁盘故障时仍能级联解锁的 RAID 阵列，可以为每块盘配置**冗余**的 LINK_OPEN 条目——每块盘连接到其他所有盘，全部带上 `SHORTCUT` 标志。某条链接成功时，同级其余链接被剪掉；某条链接失败（磁盘丢失）时，下一条链接自动接替。

**3 盘 RAID 5**（容忍 1 盘故障）：每块盘两条冗余链路，低优先级先尝试，全部带 `SHORTCUT`：

```bash
# 第一步：在每块盘上创建 Windham 分区
for dev in /dev/sda /dev/sdb /dev/sdc; do
    sudo windham New $dev --key=raid密码
done

# 第二步：每块盘添加冗余链路
# 盘 A → B（优先级=50, SHORTCUT）、C（优先级=100, SHORTCUT）
sudo windham Aux /dev/sda --key=raid密码 \
    --aux-add-link=/dev/sdb --aux-target-key=raid密码 --aux-link-prio=50 --aux-link-flag=SHORTCUT
sudo windham Aux /dev/sda --key=raid密码 \
    --aux-add-link=/dev/sdc --aux-target-key=raid密码 --aux-link-prio=100 --aux-link-flag=SHORTCUT

# 盘 B → C（优先级=50, SHORTCUT）、A（优先级=100, SHORTCUT）
sudo windham Aux /dev/sdb --key=raid密码 \
    --aux-add-link=/dev/sdc --aux-target-key=raid密码 --aux-link-prio=50 --aux-link-flag=SHORTCUT
sudo windham Aux /dev/sdb --key=raid密码 \
    --aux-add-link=/dev/sda --aux-target-key=raid密码 --aux-link-prio=100 --aux-link-flag=SHORTCUT

# 盘 C → A（优先级=50, SHORTCUT）、B（优先级=100, SHORTCUT）
sudo windham Aux /dev/sdc --key=raid密码 \
    --aux-add-link=/dev/sda --aux-target-key=raid密码 --aux-link-prio=50 --aux-link-flag=SHORTCUT
sudo windham Aux /dev/sdc --key=raid密码 \
    --aux-add-link=/dev/sdb --aux-target-key=raid密码 --aux-link-prio=100 --aux-link-flag=SHORTCUT
```

**容错原理**——以打开盘 A 为例：

| 盘 A 的链路 | B 存活？ | C 存活？ | 级联结果 |
|---|---|---|---|
| B(50,SHORTCUT) → C(100,SHORTCUT) | ✓ | ✓ | B 打开 → SHORTCUT 剪掉 C。三盘全开。 |
| B(50,SHORTCUT) → C(100,SHORTCUT) | ✗ | ✓ | B 失败。C 打开 → SHORTCUT 生效（同级已无兄弟）。A + C 打开。 |
| B(50,SHORTCUT) → C(100,SHORTCUT) | ✓ | ✗ | B 打开 → SHORTCUT 剪掉 C。B→A 被跳过（A 已打开）。A + B 打开。 |

对于 **RAID 6**（5 盘以上，容忍 2 盘故障），每块盘需要 4 条冗余链路（指向其余全部盘），全部带 SHORTCUT。级联会自动找到一条穿过所有存活盘的路径。

等所有存活盘的映射设备都出现在 `/dev/mapper/` 下之后，再单独执行 `mdadm` 组装：

```bash
sudo windham Open /dev/sda --key=raid密码
sudo mdadm --assemble /dev/md0 /dev/mapper/windham-*
```

如需开机自动完成，可用 windhamtab 的 pass 排序：第一步 pass 执行级联解锁，第二步 pass 调用 `mdadm` 组装。

### 根分区联动

把 home 分区链接到 root 分区，一次解锁就能联动打开：

```bash
# 将加密的 /home 链接到加密的 /root
windham Aux /dev/root --key=root密码 \
    --aux-add-link=/dev/home --aux-target-key=home密码 --aux-link-prio=50 --aux-link-flag=SHORTCUT
```

### 离线备份链条

构造一条链，使解锁主设备的同时也将远端的备份设备（插上时）一并解锁：

```bash
windham Aux /dev/primary --key=主密码 \
    --aux-add-link=/dev/disk/by-uuid/<备份盘UUID> --aux-target-key=备份密码 --aux-link-prio=200
```

### 自动化 RAID 配置脚本

`scripts/windham-raid-setup.sh` 一键完成容错多盘部署：

```bash
# RAID6：4 盘，每盘链接下 3 盘（容忍 2 盘故障）
sudo ./scripts/windham-raid-setup.sh --raid=raid6 --pass=raid密码 /dev/sd{b,c,d,e}

# RAID5：5 盘，链接下 2 盘（容忍 1 盘故障）
sudo ./scripts/windham-raid-setup.sh --raid=raid5 /dev/sd{a,b,c,d,e}

# 全冗余：每盘链接所有其他盘
sudo ./scripts/windham-raid-setup.sh --pass=我的密码 /dev/sd{a,b,c}
```

脚本自动完成：
1. 共享级联密钥生成
2. 分区创建 + 用户口令注册
3. 带 SHORTCUT 的冗余 LINK_OPEN 条目
4. 每盘添加 SHELL 命令（`mdadm --assemble /dev/md0 @`）带 BLCKOPEN
5. 每盘添加公共 "RAID 成员" 警告标签

配置完成后，打开第一块盘即可解锁并自动组装：

```bash
sudo windham Open /dev/sdb
# 全部盘级联解锁 → SHELL 执行 → /dev/md0 就绪
```

| 脚本选项 | 取值 | 说明 |
|---|---|---|
| `--raid=` | `all`（默认）、`raid5`、`raid6` | 链路拓扑 |
| `--pass=` | 字符串 | 用户密码（省略则提示输入） |
| `--open-first=` | 设备路径 | 级联触发盘（默认第一个参数） |
| `--dry-run` | — | 打印命令但不执行 |

## 辅助数据区管理

| 命令 | 功能 |
|---|---|
| `--aux-add=<内容>` | 添加一条纯文本条目 |
| `--aux-add-command=<命令> --aux-flag=<标志>` | 添加一条 Shell 命令条目 |
| `--aux-add-link=<路径> --aux-target-key=...` | 添加一条链接解锁条目 |
| `--aux-del` | 删除当前密钥对应的所有条目 |
| `--aux-probe` | 列出当前密钥对应的条目 + 所有公开条目 |

所有操作都需要先解锁辅助数据区——用 `--key`、`--key-file` 或 `--keystdin`。

### 查看条目

```bash
# 列出当前密钥加密的全部条目以及公开条目
windham Aux /dev/sda --key=我的密码 --aux-probe

# 用主密钥解锁时，只会列出公开条目
windham Aux /dev/sda --master-key=<十六进制主密钥> --aux-probe
```

### 删除某密钥的全部条目

```bash
windham Aux /dev/sda --key=我的密码 --aux-del
# 会移除所有由该口令哈希值加密的辅助数据条目
```
