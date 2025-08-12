_该 Readme 为英文原文的简体中文翻译。其更新可能不如英文原文及时。_

# Windham

Windham 是一款用于磁盘加密的自由软件。它基于 Linux 内核的 dm-crypt 模块，是其独立规范的实现。



&nbsp;

__注意：Windham 目前处于早期开发阶段。未来版本可能会引入不兼容的磁盘格式（尽管不太可能）；使用的话风险自负！__

&nbsp;

# 支持的功能：

- 透明且实时的磁盘（或分区）加密。
- 可抵赖性：完全无标记且密码学随机的磁盘格式实现。也就是说，没人能100%指出某个分区是使用 Windham 加密的，而非没用的随机数据。可选支持“诱饵分区”：将自己隐藏在一个普通文件系统之下。
- 密码管理：支持注册多个（最多16个）密码、密码文件和/或密钥。
- 快速：得益于其密码学随机的磁盘格式，解锁时间与注册的密码数量无关；始终与仅注册一个密码时一样快。
- 防篡改：磁盘格式设计用于防止恶意篡改。
- 自关联元数据：Windham 会将每次修改纠缠到多个间接区域，从而极大降低通过比较修改前后磁盘格式提取信息的有效性。

Windham 结合了 cryptsetup 加 LUKS/LUKS2 的灵活性、功能性和安全性，同时提供了类似于 VeraCrypt 的可抵赖性和隐藏卷功能。其能够在注册任意数量密码时以恒定时间解锁的能力，超越了当前所有存储加密方案。

&nbsp;

# 如何安装？

Windham 需要基于 Linux 内核的类 UNIX 系统；大部分测试在 GNU/Linux 下完成。对于这些操作系统，需要安装[完整支持模式的依赖项](#完整支持的依赖项)。

以下命令将在 `./windham/dev` 下编译 Windham。需要 Git、CMake 3.16+ 和兼容 ISO C11 的编译器。这些命令适用于大多数现代 shell 和不同操作系统。

```shell
git clone https://github.com/level-128/windham.git --depth=1
cd windham
cmake -B build
cd build
cmake --build .
```

在类 GNU 系统上，上述命令默认使用 `Release` 构建类型，会在该平台下构建功能完整的 Windham。**构建 `Release` 前需安装依赖项。**  
对于其他平台，默认启用仅支持 ISO C 的构建类型，提供一组基本的磁盘格式管理操作。详见：[支持的平台](#支持的平台)。

&nbsp;

# 快速使用指南：

1. 在 `/dev` 下找到要创建加密分区的设备，可使用图形磁盘管理器（如 GNOME Disks、Gparted）或命令 `lsblk`。设备名可能是 `/dev/sdb` 或 `/dev/nvme0n1`；若选择创建加密分区而非整盘加密，则可能是 `/dev/sdb2` 或 `/dev/nvme0n2p2`。
2. 使用 `windham New *设备名*` 创建新的 Windham 设备。例如：在 `/dev/sdb` 上创建 Windham 设备，运行 `sudo windham New /dev/sdb`。
3. 要打开并映射设备，使用 `windham Open *设备名*`。例如：`sudo windham Open /dev/sdb --to=enc1` 会打开 `/dev/sdb` 并映射到 `/dev/mapper/enc1`。
4. 像空磁盘一样创建文件系统。可使用图形磁盘管理器或 `mkfs`。例如：用 `sudo mkfs.ext4 /dev/mapper/*名称*` 创建 ext4 分区。
5. 使用完毕后，用 `windham close *名称*` 关闭并锁定设备。
6. （可选但强烈推荐）运行 `windham Open *设备名* --dry-run` 查看主密钥；将其备份到安全位置。  
   **主密钥可访问、控制和修改整个分区。一旦泄露，无法重新生成！**

&nbsp;

- 操作 `Suspend` 可挂起加密——将中间密钥以明文形式记录到头中，允许任何人访问加密分区。此操作同样防篡改，且无法从中推导出密码或主密钥。使用 `Resume` 可取消挂起。  
  **注意：** Windham 和 cryptsetup 的 `Suspend` 含义不同：在 cryptsetup 中，它表示暂停加密设备的读写。
- 使用 `AddKey` 和 `DelKey` 添加或删除密钥。根据威胁模型，若认为攻击者无法在 `--rapid-add` 前后同时访问设备，可使用该选项。否则，攻击者在暴力破解密码时将获得显著优势。  
  通常冷存储加密方案无需防御此类威胁模型。不带 `--rapid-add` 的 `AddKey`（默认）无此漏洞，但在已注册多个密码时速度较慢。

&nbsp;

# 支持的平台：

Windham 有两个功能支持级别：

1. **完整支持**：Linux 内核 2.6+（推荐启用内核密钥保留服务的 5.14+ 内核）。无额外 libc 要求。
2. **基本模式**：严格兼容 ISO C11。目标系统需满足以下要求：
    - 8 位字节，补码表示有符号整数；字节序为大端或小端。
    - 基础字符集（定义为单字节可表示字符）需包含 ISO C "C" 区域设置的所有字符；a-z、A-Z 和 0-9 必须连续编码。（ASCII 符合此要求）
    - 系统需提供托管环境，或完全实现 `stdlib.h`、`string.h` 和 `stdio.h` 的独立环境。
    - 系统堆（或动态分配）至少需 492,000 字节空闲内存，其中 464,000 字节需在地址空间中连续。64 位平台执行到 `main` 函数时，栈大小至少需 `25,968 + sizeof(FILENAME_MAX) * 2` 字节。32/16 位平台栈需求略低。
    - __（可选）__ ISO C 线程实现。

ISO C 模式下的 Windham 无法挂载和操作（加密/解密）分区，不设计为在 pid1 下运行，无法解析 `/etc/windhamtab`，也无法通过 UUID 或设备路径搜索磁盘/设备。访问分区/磁盘的能力完全取决于平台的 libc 实现：若需平台相关接口读取分区/磁盘而非通用文件 I/O，则无法使用。部分次要功能可能缺失。但解锁、提取主密钥、管理密码和挂起支持在基本模式下均可用。

几乎所有现代消费设备均满足基本模式要求。大多数具有完善开发框架或社区支持的 32 位 MCU 或 SoC 也可运行。兼容 libc 的虚拟环境（如 WebAssembly）可能开箱即用（或需小幅修改以解决文件权限问题）。但若无操作系统环境或标准化裸机框架（如 FreeRTOS Plus FAT 和 POSIX）处理文件 I/O 或提供解锁后端（如命令行 TCG Opal 框架），运行 Windham 技术上可行但基本无用。

ISO C 模式下嵌入解锁后端的说明见源文件 `libplat/ISOC/mapper.c`。

&nbsp;

# 其他指南：

## `/etc/windhamtab` 支持与加密模块集成

完整支持下的 Windham 支持 `/etc/windhamtab` 文件，用于描述加密的 Windham 设备。此文件类似于 systemd 的 `/etc/crypttab`，使用 `windham Open TAB` 时会读取该文件。详情见 `/etc/windhamtab` 提交记录。配置步骤如下：

1. 首次运行 `windham Open TAB` 时，若文件不存在，则创建模板 `windhamtab` 文件。
2. 根据文件注释的格式写入加密设备和目标路径（位于 `/dev/mapper`，同 `Windham Open` 的 `--to` 参数），以及参数和解密方法。`windhamtab` 支持通过密钥、密钥文件或 Clevis 解锁。强烈建议使用 `UUID=`，因其是命名设备的可靠方式，即使磁盘增减也不受影响。
3. 使用 Clevis 解锁时，在密钥字段用 `CLEVIS=` 指定 Clevis 文件。以 systemd 为 init 的用户（多数发行版都用），stdin 由守护进程本身处理；
   需要使用 `systemd-dialog` 选项与 systemd 和 plymouth（若使用图形启动屏幕）集成，否则将永久卡住！
4. 为需优先打开的设备分配较小的 `<pass>` 值以解决依赖关系。选项 `--windhamtab-pass` 让 Windham 仅执行相同 pass 编号的操作。
5. 存在 `windhamtab` 文件时，运行 `windham Open TAB` 将开始解析该文件。

多数现代消费设备支持内置 TPM（可信平台模块）或其他外部硬件安全模块（如 FIDO 设备）。要利用这些设备，需自动化加密框架如 [`clevis`](https://github.com/latchset/clevis)。注册随机密钥供 Clevis 通过 TPM2 加密：

```
sudo windham AddKey <设备> --generate-random-key | sudo clevis encrypt tpm2 '{}' > keyfile.key
```
Clevis 密钥将创建为 `keyfile.keyfile`。解锁时：
```
cat keyfile.key | sudo clevis decrypt tpm2 '{}' | sudo windham Open <设备> --keystdin
```
在 `/etc/windhamtab` 中，密钥参数使用 `CLEVIS=` 前缀即可集成 Clevis。

&nbsp;

## 诱饵分区

Windham 支持诱饵分区：为加密分区提供高程度可抵赖性的功能。

### 什么是诱饵分区？

诱饵分区允许 Windham 隐藏其加密分区。当有人强迫你披露磁盘上的机密数据，或分区头的随机性本身不足以强有力反驳其存在时，诱饵分区可让你否认加密分区的存在。

诱饵分区通过隐藏在相同区域的标识性分区下（通常是分区表的最后一个分区/尾部空闲区域）实现高程度可抵赖性。诱饵分区的大小通常远小于标识性分区的全部空间。此外，覆盖其上的标识性分区（包括元数据、日志和数据）**必须从底部到顶部扇区在空间上线性排列**，否则诱饵分区可能因被覆盖而损坏。

### 如何启用诱饵分区？

使用 `windham New *设备名* --decoy` 创建加密分区时同时创建诱饵分区。打开诱饵分区时，使用 `--decoy` 参数（`Close` 除外）；程序会将给定设备识别为诱饵分区。创建时用 `--decoy-size` 指定诱饵分区大小。求解器会判断给定大小是否可行（如诱饵分区不能跨越分区表定义的边界）。

强烈建议在部署诱饵分区和标识性分区前用随机数据覆盖设备：`sudo dd if=/dev/urandom of=/dev/<设备名>, bs=16M`。诱饵分区的机密性基于隐蔽性；跳过随机覆盖会使其在面对经验丰富的攻击者时，可抵赖性基本归零。

### 使用诱饵分区的注意事项

诱饵分区可创建在普通 Windham 分区能创建的任何位置。此外，在普通 Windham 分区内创建诱饵分区的组合会进一步提升可抵赖性，因为加密分区内外的数据天然呈现随机性。

若设备使用 GPT 分区表（基本都是），情况略有不同：GPT 分区表使用最后几个扇区存储备份。因此 Windham 会将诱饵分区的头定位在 GPT 备份之前。Windham 
会主动探测 GPT 布局以决定头位置，确保 GPT 结构永不损坏。诱饵分区头的位置因 GPT 结构而异。

多数分区软件将分区对齐到 1MiB 边界，而 Windham 头远小于 1MiB。因此对 GPT 分区的修改或创建很可能不会覆盖头。但请勿默认这个特性一定成立。

__若在创建诱饵分区后删除或创建 GPT 分区，Windham 可能无法定位原始诱饵分区头，或更可能因修改而覆盖它。__ 如果你想和你的数据说拜拜的话，这么做完全没问题。

没有任何东西可以保护或探测你在对可见的外层分区写入时会不会覆盖到底层的加密分区，所以对于文件系统，推荐使用 ExFAT 和 FAT32，因为这些文件系统默认从底部到顶部扇区线性写入，EXT4 则没有这种特性。

TRIM 问题：多数内置 SSD 支持 TRIM（逻辑块丢弃）。TRIM 允许设备标记无效区域，供硬件内部交换。在支持 TRIM 的 SSD 上创建诱饵分区时，攻击者可直接
发现未标记为丢弃的随机巨大数据块，从而让可抵赖性直接归零。建议禁用 TRIM；若需降低嫌疑，可使用 USB 闪存盘（这些通常没 TRIM）或机械硬盘。
部分机械硬盘（多为叠瓦式磁记录 SMR 磁盘）支持 TRIM，但控制器读取丢弃扇区时会返回上面原样的数据，并且扇区交换的频率极低。

&nbsp;

## 在早期用户空间运行 Windham

Windham 设计支持早期用户空间操作（如解密加密的根目录）。_请勿在 PID 1 下运行 ISO C 构建_。推荐以下两种方法：

### 使用 init 守护进程：
此方法与多数 GNU/Linux 发行版推荐的行为一致。使用 `windham Open TAB` 时，Windham 会解析 `/etc/windhamtab` 文件操作。此时所有操作由 Windham 自身处理，兼容多种 init 系统。推荐使用 `windhamtab` 文件，避免直接使用命令行（如 `Windham Open /dev/sda ...`）。

为此，为 init 守护进程创建目标 `exec=windham Open TAB`。该目标需在 init 进程挂载目标分区前执行。

注意：部分发行版使用 initrd 或 initramfs。若需加密根目录，查阅发行版自身的文档或用于打包 initrd 或 initramfs 的文档（如 dracut）来确保
Windham 和 Clevis 包含在包中；因为它依赖 chroot 目标，所以要在 chroot 服务前执行。

### 以 pid1 运行 `windham`：

此方法仅适用于嵌入式 Linux 系统。**完整 GNU/Linux 发行版切勿使用**。

Windham 检测到以 pid1 运行时行为不同。此时会忽略命令行，使用二进制中的预设。可通过十六进制编辑器修改预设命令行（默认为 `windham Open TAB`，然后执行 `/bin/sh`）。

预设命令行位于 `.windhaminit` 段，语法如下：
```
WINDHAMINIT:\xff<成功后的执行程序>\xff<操作>\xff<参数>\xff<选项>...
```
```Bash
# 搜索目标段
objdump -h a.out | grep windhaminit
# 用十六进制编辑器修改...
hexedit /windham/bin/location
```
各元素以 `0xff` 分隔，字符串以 `0x00` 结尾，长度不超过 255 字符。所有消息打印到内核 `dmesg`。要以 pid1 运行 Windham，启动时使用 `init=` 内核参数。嵌入式系统建议直接执行单个 Open 操作而非读取 `/etc/windhamtab`。

若 Windham 作为 pid1 运行失败，程序将退出，导致内核恐慌：`Kernel panic - not syncing - Attempted to kill init!`。此行为符合预期；若非如此，使用 `--nofail` 选项，失败时不执行任何操作并启动给定可执行文件。

&nbsp;

# 构建 Windham：
## 完整支持的依赖项：

完整支持需兼容 GNU 风格的 `__attribute__` 和语言扩展的类 GCC 编译器。

| 描述                     | Debian 系          | Fedora 系 / SUSE     | Arch 系        |
|--------------------------|--------------------|----------------------|---------------|
| 设备映射器               | `libdevmapper-dev` | `device-mapper-devel`| `device-mapper` |
| 内核头文件               | `linux-headers-$(uname -r)` | `kernel-devel` | `linux-headers` | 
| GNU Gettext              | `libgettextpo-dev` | `gettext-runtime`    | `gettext`     |
| libblkid 库              | `libblkid-dev`     | `libblkid-devel`     | `util-linux`  |
| 内核密钥保留服务（可选） | `libkeyutils-dev`  | `keyutils-libs-devel`| `keyutils`    | 

其他可选用户空间程序（缺失时部分选项不可用）：
- `clevis`：自动化加解密的插件框架。
- `partx`：向内核通知磁盘分区存在及编号的用户空间工具。

&nbsp;

## 交叉编译与功能开关

构建系统支持以下功能开关：
- `CFG_NO_MODULE_KEYRING`：禁用内核密钥保留服务
- `CFG_WINDHAM_ALLOW_ATTACH`：允许调试器附加（`Debug` 配置默认）
- `CFG_NO_ENFORCE_SPEC_MITIGATION`：不强制 Spectre 缓解（`Debug` 配置默认）
- `CFG_NO_OPT`：禁用 SIMD 优化（仅 x86-64 可用）
- `CFG_USE_SWAP`：允许内存换页到交换空间（极不安全！建议启用 `CFG_WIPE_MEMORY`！）
- `CFG_WIPE_MEMORY`：密钥派生后清除内存

使用 `cmake -B build -D YOUR_OPTION=TRUE` 切换功能开关。

`ISOC` 构建类型几乎等同于直接用编译器编译 `frontend.c`（加上常见 UNIX 编译器的预设优化选项）。除此之外别无其他。严格 ISO C11 配置下构建系统可选，功能开关无效。最快交叉编译方式是直接调用编译器。

&nbsp;

Windham 支持交叉编译 `Release` 构建类型。与其他 CMake 项目一样，请先参考 CMake 手册：[交叉编译](https://cmake.org/cmake/help/book/mastering-cmake/chapter/Cross%20Compiling%20With%20CMake.html)。  
交叉编译示例（从非 x86-64 主机到 x86-64，禁用 x86 特定优化）：
```shell
# 安装交叉工具链
sudo apt install gcc-x86-64-linux-gnu 
cmake -D CMAKE_SYSTEM_NAME=Linux\
 -D CMAKE_SYSTEM_PROCESSOR=amd64\
 -D CFG_NO_OPT=TRUE\
 -D CMAKE_C_COMPILER=x86_64-linux-gnu-gcc\
 -B build
cd build
cmake --build .
```

`Release` 构建类型下，`try_run` 无效。Windham 假设：能编译就能无错运行/启用最佳功能集。若非所需，用上述功能开关禁用特定功能。

[Crosstool-NG](https://crosstool-ng.github.io/) 和 [ZigCC](https://ziglang.org/download/) 是交叉编译到托管平台的实用工具。Zig cc 是 Zig 编译器的子命令，兼容 GCC 和 Clang。

&nbsp;

# 安全考量

Windham 实现了结合合理推诿性的尖端存储加密方案。但不存在万全之策：为缓解或消除多种攻击向量必须做出某些妥协。本节内容仅适用于"安全偏执狂"，大多数用户永远不会成为这些攻击的目标。

在继续之前，我们需要介绍与Windham内部机制相关的几个概念：
- 头部重构变换：更改新的头部向量后，将头部重新计算为等效形式，但绝大多数比特位都会改变（包括密钥槽字段和元数据字段）
- 匿名密钥：匿名密钥没有标识符，且无法在重构变换后保留。使用`DelKey`操作时可通过`--anonymous-key`选项使密钥匿名化
- KDF迭代：KDF是密钥派生函数（Key Derivation Function）的缩写。Windham使用Argon2id进行密码迭代，每次迭代具有可变的内存消耗偏置。目标内存将随迭代次数呈指数级增长

## 密钥槽历史记录攻击
当攻击者能物理接触设备，且在使用`--rapid-add`选项执行`AddKey`操作时对比操作前后的头部差异，攻击者将获得显著优势来暴力破解密码短语——因为`--rapid-add`选项意味着尽可能禁止头部重构变换。

Windham对此攻击设有基础防护机制：使用`--rapid-add`时会广播多个无关区域。即便经过防护，若攻击者能在`AddKey --rapid-add`操作前后都接触
设备，仍能获得约30-100倍的破解时间优势。Windham默认不启用`--rapid-add`选项，因此每次都会执行头部重构变换。

## 密钥标识符攻击
若攻击者能访问设备（使用其某个密码或主密钥），相对于其他已注册的非匿名密码，攻击者将获得约4-5个数量级的计算优势。系统会存储KDF迭代第一阶段后的中间密钥，该记录的中间密钥采用小得多的Argon2id内存成本参数，用于在重构变换期间保留密码，并在使用`--dry-run`时打印内部标识符。以下情况不受此攻击影响：

- 注册密码的熵值大于SHA256的输出熵（32字节）。换言之：猜解密码比猜解最终磁盘密钥更困难（通常适用于大多数密钥文件或用于Clevis集成的密钥）
- 注册密码为匿名密码
- 仅注册单个密码且主密钥未被泄露

## 侧信道攻击
每次KDF迭代期间，内存成本参数会根据前次哈希结果和头部向量产生波动。仅当KDF迭代需要21.93MiB内存时才会触发此波动，波动幅度范围为0.013%至0.02%（当KDF内存成本达到220.4TiB时——这对未来可预见的大多数系统基本不可能实现）。这种内存成本波动机制将阻碍攻击者定制硬件来加速KDF运算。

攻击者可能通过测量正在解锁设备的功耗/电磁辐射时间，或通过其他恶意进程直接计时。现代计算设备的CPU具有复杂缓存层次结构，操作系统采用抢占式多任务，CPU速度受温度等因素影响，要在波动幅度对应的时间精度内测量执行时间（由于Argon2的特性使缓存未命中不可预测）几乎不可能。但这在微控制器(MCU)上可能实现——它们具有简单的缓存设计、恒定时钟周期及恒定指令周期，实时操作系统(RTOS)具有可预测的多任务调度器。目前大多数MCU不会在时间预算内为KDF分配超过21.93MiB内存，但未来可能出现这种情况。

内存方面，Windham会为每次KDF迭代分配波动范围的上限值。通过测量缺页异常可能实施侧信道攻击，Windham将尽可能使用大内存页来缓解此类测量。

## 磁盘格式标识
大多数磁盘格式或文件系统都有魔数以自我标识，使内核或其他软件能识别并挂载管理它们。Windham不依赖磁盘格式标识（这会导致丧失合理推诿性），但按惯例保留了一个标识符（ASCII编码的`WINDHAMWINDHAMWI`）。程序本身会忽略分区前16字节的标识符存储区，但建议其他软件可搜索此标识符。

如需移除该标识符，请使用：`dd if=/dev/urandom of=/dev/your_disk bs=16B count=1`

&nbsp;

# 贡献：

:) 欢迎贡献 :)

Windham 在 `Release` 构建类型下不可调试，应使用 `Debug` 构建类型。GNU 系统是主要开发平台，推荐使用 glibc 扩展在崩溃时打印栈追踪。

请确保已阅读[行为准则](/CODE_OF_CONDUCT.md)。

&nbsp;

# 许可证与法律问题

版权所有 (C) 2023, 2024, 2025 level-128

本程序是自由软件：您可依据自由软件基金会发布的 GNU 通用公共许可证第3版或（任意选择）后续版本重新发布或修改它。

早期版本授予了“附加权限”（依据GNU GPLv3条款7），适用于未修改的覆盖作品的传播。自 0.231128 版（2023年11月28日发布）起，“附加权限”已移除。

自 1.241231 版（2024年12月31日发布）起，许可证从仅 GPLv3（GPLv3 only）改为 GPLv3 及以后版本（GPLv3 or later）。

本软件包含第三方自由软件。详见[许可信息](/library/license.md)。

### 美国加密出口条例

Windham 归类于 ECCN 5D002，提供或执行 EAR 772 部分定义的“非标准加密”，受工业与安全局出口管理条例管辖。加密功能更新或修改时，需通过电子邮件向 BIS 和 ENC 加密请求协调员提交源代码的互联网地址（如 URL）。

若您居住在美国或被定义为美国人，发布更改前需提交 BIS 合规证明。

### 实施数字版权管理（DRM）或数字反规避方案

GPLv3 第3条：_保护用户免受反规避法的法律权利侵害。_  
Windham（及基于 Windham 的作品，定义见“覆盖作品（Covered Work）”）不得被视为任何适用法律下的有效技术措施，该法律履行 1996 年 12 月 20 日通过的 WIPO 版权条约第 11 条或类似禁止或限制规避此类措施的法律义务。  
传播覆盖作品时，您放弃任何法律权力以禁止规避技术措施，只要该规避是通过行使本许可证赋予的权利实现的，且您否认任何意图通过限制作品操作或修改来对抗作品用户，以执行您或第三方禁止规避技术措施的法律权利。
```