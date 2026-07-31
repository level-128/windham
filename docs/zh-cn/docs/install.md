# 安装与构建

## 完整模式（GNU/Linux）

### 系统依赖

| 软件包 | Debian/Ubuntu | Fedora/RHEL | Arch | 备注 |
|---|---|---|---|---|
| 内核头文件 | `linux-headers-$(uname -r)` | `kernel-devel` | `linux-headers` | 必需 |
| Gettext（可选） | `libgettextpo-dev` | `gettext-runtime` | `gettext` | 用于国际化翻译 |
| libblkid（可选） | `libblkid-dev` | `libblkid-devel` | `util-linux` | 分区表检测，运行时尝试连接 |
| keyutils（可选） | `libkeyutils-dev` | `keyutils-libs-devel` | `keyutils` | 内核密钥保留服务，运行时尝试连接 |

可选的运行时程序：`clevis`、`partx`。

### 构建

```bash
git clone https://github.com/level-128/windham.git --depth=1
cd windham
cmake -B build
cmake --build build
# 生成的可执行文件：build/windham
```

调试版本（允许调试器附加，输出更详细）：

```bash
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug -DCFG_USE_SWAP=1
cmake --build cmake-build-debug
```

### 编译选项

通过 `-D<选项名>=TRUE` 传递给 cmake：

| 选项                                   | 作用                              |
|--------------------------------------|---------------------------------|
| `CFG_NO_MODULE_KEYRING`              | 禁用内核密钥保留服务                      |
| `WINDHAM_NO_DISABLE_ATTACH`          | 允许调试器附加到进程（Release 构建下）           |
| `WINDHAM_NO_ENFORCE_SPEC_MITIGATION` | 跳过 Spectre 漏洞缓解                 |
| `WINDHAM_NO_SECCOMP`                 | 禁用 seccomp 过滤器                  |
| `CFG_NO_OPT`                         | 关闭 x86-64 SIMD 优化               |
| `CFG_USE_SWAP`                       | 允许 KDF 使用交换空间（⚠ 不安全）            |
| `CFG_WIPE_MEMORY`                    | KDF 完成后清零工作内存                   |
| `CFG_32BIT_ADDR_SPACE`               | 32位地址空间下限制 Argon2 内存            |
| `CFG_DRIVER_NO_FF`                   | 禁用 FatFs 交互式 Shell 驱动           |
| `CFG_NO_FF_CREATE`                   | 禁用 --create-exfat 创建 exFAT 文件系统 |
| `CFG_DRIVER_NO_DECRYPT`              | 禁用全盘解密驱动                        |
| `WINDHAM_REPRODUCIBLE_BUILD`         | 用固定字符串替换构建时间戳/内核版本              |
| `WINDHAM_NO_ISOC_THREAD`             | 禁用多线程支持                         |
| `CFG_FF_SHELL_NOINTERACTIVE`         | 非交互模式，从 ./cmd_queue 文件读取命令      |
| `CFG_VFS_DISK_METADATA`              | 从 ./disk_size 文件读取磁盘大小            |
| `CFG_ASCII`                          | 强制 ASCII 模式（屏蔽 UTF-16/UTF-32）    |

---

## Web 构建（Emscripten / WebAssembly）

Windham 可编译为 WebAssembly 在浏览器中运行。Web 版本提供基于 FatFs 的只读
交互式 Shell——可直接在浏览器中浏览、导航和下载 exFAT/FAT32 磁盘镜像中的文件。
所有解密操作均在 WebAssembly 中本地完成，数据不会离开您的计算机。

### 前置条件

- [Emscripten](https://emscripten.org/docs/getting_started/downloads.html)（已测试 6.0+）
- Node.js（emsdk 需要）

### 构建

```bash
# 安装并激活 emsdk
cd ~
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install latest
./emsdk activate latest

# 构建 Windham
cd ~/windham
source ~/emsdk/emsdk_env.sh
emcmake cmake -B build/web -S web
cmake --build build/web
```

输出文件：`build/web/windham.js`、`build/web/windham.wasm`，以及 Web 前端文件
（`index.html`、`app.js`、`worker.js`）。

### 启动服务

应用需要 `Cross-Origin-Opener-Policy` 和 `Cross-Origin-Embedder-Policy`
HTTP 头以支持 `SharedArrayBuffer`：

```bash
python3 web/serve.py
# → http://localhost:8000
```

### 架构说明

Web 构建是独立的 CMake 项目（`web/CMakeLists.txt`），**不使用**主 `CMakeLists.txt`。
关键设计决策：

- **文件 I/O**：用户选择的文件通过 `File.slice()` + `FileReaderSync` 在 Web Worker
  内按需读取——整个磁盘镜像**不会**加载到内存。

- **驱动**：使用 FatFs Shell 驱动（`driver_ff`），非交互模式（`CFG_FF_SHELL_NOINTERACTIVE`）。
  命令通过 `/cmd_queue` 传递。

- **文件系统**：Emscripten MEMFS 将加密磁盘镜像暴露为 `/disk.img`，
  使用自定义 stream_ops 后端将每次 `fread`/`fwrite`/`fseek` 代理为分块文件读取。

- **ASYNCIFY**：FatFs Shell 事件循环需要 ASYNCIFY（`emscripten_sleep`）。
  栈大小增加至 64 KiB（`ASYNCIFY_STACK_SIZE=65536`）
  以适应深层加密 I/O 调用栈。

### 创建 Web 用的磁盘镜像

```bash
# GNU/Linux（任何支持 dm-crypt 的平台）
windham New disk.img --diskfile=64MiB --key=密码 --create-exfat
```

然后将 `disk.img` 拖入网页，输入密码即可。

---

## 交叉编译

Windham 支持交叉编译到其他硬件平台：

```bash
# 在 x86-64 主机上编译 ARM64 目标
cmake -B build \
    -D CMAKE_SYSTEM_NAME=Linux \
    -D CMAKE_SYSTEM_PROCESSOR=aarch64 \
    -D CMAKE_C_COMPILER=aarch64-linux-gnu-gcc
cmake --build build
```

交叉编译时 `try_run` 无法执行——Windham 会假定能够编译的功能均可正常运行。请使用上面的编译选项显式开启或关闭特定功能。

---

## musl 静态构建（嵌入式 / initramfs）

可以用 musl libc 构建完全静态的二进制（零 `.so` 依赖），适用于嵌入式 Linux、
initramfs 或最小容器镜像。

### 前置条件

```bash
# Debian / Ubuntu
sudo apt install musl-tools musl-dev
```

### 构建

```bash
CC=musl-gcc CFLAGS="-idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu" \
  cmake -DCMAKE_EXE_LINKER_FLAGS="-static" -DCMAKE_BUILD_TYPE=Release \
  -B build-musl
cmake --build build-musl
```

`-idirafter` 标志让 musl-gcc 在 musl 自带的头文件路径之后、作为后备搜索内核头文件
（`<linux/dm-ioctl.h>`、`<blkid/blkid.h>` 等），避免了 glibc 与 musl 头文件之间的冲突。

### 验证

```bash
file build-musl/windham
# ELF 64-bit LSB executable, statically linked, ...

ldd build-musl/windham
# not a dynamic executable
```

### 运行时要求

静态二进制只需要：
- 内核编译有 `CONFIG_BLK_DEV_DM` 和 `CONFIG_DM_CRYPT`（用于 dm-crypt）
- `/dev/mapper/control`（devtmpfs 自动提供）
- 可选：目标系统上的 `libblkid.so`、`libkeyutils.so`（通过 `dlopen` 运行时加载；
  没有也能正常运行）

目标系统不需要 musl 的共享库——libc 已完整链接进二进制。

### musl 内核头文件的替代方案

若 `musl-gcc` 找不到内核头文件（如 `<linux/dm-ioctl.h>`），可在本地目录创建符号链接
以避免 glibc 头文件冲突（使用x86-64设备举例）：

```bash
mkdir -p ~/musl-kernhdrs
ln -s /usr/include/linux       ~/musl-kernhdrs/linux
ln -s /usr/include/asm-generic ~/musl-kernhdrs/asm-generic
ln -s /usr/include/x86_64-linux-gnu/asm ~/musl-kernhdrs/asm

CC=musl-gcc CFLAGS="-I$HOME/musl-kernhdrs" \
  cmake -DCMAKE_EXE_LINKER_FLAGS="-static" -DCMAKE_BUILD_TYPE=Release \
  -B build-musl
```

---

## ISO C11 基础模式

基础模式只需直接编译 `frontend.c`，不需要 CMake 构建系统——任何 C11 编译器都可以：

```bash
cc -std=c11 -DWINDHAM_ISOC frontend.c -o windham
```

### 基础模式的要求

- 8 位字节，补码整数表示
- 兼容 ASCII 的字符集（a–z、A–Z、0–9 必须连续编码）
- stdlib.h、string.h、stdio.h 完整实现
- 堆内存约 492 KB（其中 464 KB 必须连续）
- 64 位平台栈空间约 74 KB + 2×FILENAME_MAX（32 位平台略少）

### 与完整模式的功能对比

| 功能 | 完整模式 (GNU/Linux) | 基础模式 (ISO C11) |
|---|---|---|
| dm-crypt 挂载与读写 | ✓ | ✗ |
| 解析 /etc/windhamtab | ✓ | ✗ |
| 扫描 /proc/partitions 探测设备 | ✓ | ✗ |
| 根据 UUID 定位设备 | ✓ | ✗ |
| 内核密钥保持服务 | ✓ | ✗ |
| 加密头创建/读取/写入 | ✓ | ✓ |
| 添加/删除密钥 | ✓ | ✓ |
| 悬置/恢复 | ✓ | ✓ |
| 备份/恢复/销毁 | ✓ | ✓ |
| 文件形式创建（`--diskfile`） | ✓ | ✓ |
| exFAT 格式化（`--create-exfat`） | ✓ | ✓¹ |
| 离线解密（`--decrypt`、`--print-encryption`） | ✓ | ✓ |
| FatFs 命令终端（ls、cd、cp、导出…） | ✓ | ✓¹ |
| 提取主密钥 | ✓ | ✓ |
| Argon2 密钥派生 | ✓ | ✓（没有线程支持时较慢） |
| Unicode 密码输入 | ✓ | 取决于编译器 |
| 辅助数据区读写 | ✓ | ✓ |
| 链接解锁级联 | ✓ | ✗（无 dm-crypt，无 UUID 扫描） |
| 探测单个文件 | ✓ | ✓ |
| gettext 国际化 | ✓ | ✗ |

¹ 需要 `__STDC_UTF_16__`（C11 `char16_t` / `u""` 字面量）。

### ISO C 默认驱动行为

当 ISO C 构建打开 aes-xts 加密设备时（或使用 `--decrypt` / `--print-encryption`），
默认驱动提供一个 **FatFs 交互式命令终端**，类似 UNIX 命令行，用于浏览和操作加密文件系统：

```
> ls           列出目录内容（支持 -l、-h、-a）
> ls -lh
> cd <目录>      切换目录
> cp <源> <目标>  在加密卷内复制文件
> export <源> <主机路径>  将文件导出到主机文件系统
> import <主机路径> <目标>  将主机文件导入加密卷
> help         显示所有命令
```

支持 **FAT32 和 exFAT** 文件系统。如没有 `__STDC_UTF_16__`，仅保留 `--decrypt` 和 `--print-encryption`（将解密数据写入文件）。

### 强烈建议的平台特性

ISO C 模式可以在任何符合 C11 的环境下运行，但部分"可选"的主机特性会显著影响功能和安全：

#### 多线程支持（threads.h）

| `__STDC_NO_THREADS__` 的状态 | 实际表现 |
|---|---|
| **未定义**（线程可用） | KDF 并行处理两个密钥池区域，解锁速度可能翻倍，但在内存相比于CPU较慢的系统中可能速度没有变化。随机数使用线程局部状态。 |
| **已定义**（没有线程） | KDF 单线程运行。随机数使用全局状态。功能不受影响，只慢一些。 |

#### Unicode UTF-16（`__STDC_UTF_16__`）

`--create-exfat` 和交互式 FatFs shell 驱动需要该宏。当 `__STDC_UTF_16__` 未定义时，`--create-exfat` 在运行时会打印警告后退出；FatFs shell 驱动在编译期产生 `#warning` 提示。

| `__STDC_UTF_16__` | 实际表现 |
|---|---|
| **已定义** | `--create-exfat` 可用。ISOC 构建无 dm-crypt 时，"ff" 驱动提供交互式文件系统 shell。 |
| **未定义** | `--create-exfat` 运行时打印警告后退出。FatFs shell 驱动禁用。请使用 `--decrypt` 或 `--print-encryption` 读取加密数据。 |

当编译器支持 C11 的 `char16_t` 和 `u"..."` 字符串字面量时，会自动定义该宏。大多数现代 GCC/Clang 编译器都会定义；部分嵌入式交叉编译器不会。

#### Unicode 支持（__STDC_UTF_32__）

| `__STDC_UTF_32__` 的状态 | 实际表现 |
|---|---|
| **已定义** | 可以使用 c32rtomb/mbrtoc32 做 char32_t 与多字节文本的双向转换。密码和辅助数据区条目都支持完整 Unicode。 |
| **未定义** | 所有 char32_t 转换降到纯 ASCII。非 ASCII 密码字符会被拒绝，含非 ASCII 内容的辅助数据条目会在运行时报错。**CompCert 以及不少嵌入式 C 编译器即使目标平台是 Linux 也属于这种情况。** |

在 Linux+glibc 环境下，即便编译器没有定义 `__STDC_UTF_32__`，c32rtomb/mbrtoc32 也仍然能正常使用——这个宏反映的是编译器的保证，不是 C 库的实际能力。在 musl、newlib 或裸机 C 库的环境里，Unicode 支持就完全取决于 C 库本身的实现了。

#### UNIX 随机数设备文件

基础模式启动时依次探测三个 UNIX 设备文件：

| 设备 | 用途 | 缺失时 |
|---|---|---|
| `/dev/null` | 检验写入能力 | 忽略，继续下一项 |
| `/dev/zero` | 检验零值读取 | 忽略，继续下一项 |
| `/dev/random` | 随机数种子来源 | **回退到 SHA256 确定性随机数生成器 + 用户交互输入** |

**检测过程**（`libplat/ISOC/get_entropy.c`）：

1. 向 `/dev/null` 和 `/dev/zero` 写入测试数据并读回。如果**两个**都通过 → 认定当前环境为类 UNIX 系统。
2. 类 UNIX 模式下：从 `/dev/random` 读取 32 字节作为初始种子。如果读取失败 → 进入交互模式。
3. 如果 `/dev/null` 或 `/dev/zero` 不可用 → 进入**纯 ISO C 模式**：
   - 提示用户输入任意键盘内容用作熵源（"input anything as entropy"）
   - 将用户输入与 `timespec_get(TIME_UTC)` 时间戳通过 SHA-256 混合
   - 使用 SHA-256 构建确定性随机比特生成器，具备：
     - 内部计数器和每线程状态
     - 每生成 32 次后重新混入时间戳
     - 多线程构建使用线程局部缓冲区
   - 如果系统定时器精度超过 1 毫秒，会打印警告

**纯 ISO C 随机数生成器的安全性说明**：

- 该生成器是确定性的——给定同样的种子，永远输出同样的结果。种子来自用户击键与时间戳，其熵量可能非常有限。
- **生产环境中，只应在能访问 `/dev/random` 或等效硬件熵源的平台上创建设备。** 纯 ISO C 随机数生成器适合做测试和验证，但若交互式种子质量不够，生成的主密钥和加密头随机数就可能被预测。
- 虽然定时器会定期混入生成器状态，但缺乏硬件熵源的情况下，整个系统的密码学强度完全取决于初始种子。
