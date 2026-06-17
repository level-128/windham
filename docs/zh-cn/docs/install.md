# 安装与构建

## 完整模式（GNU/Linux）

### 系统依赖

| 软件包 | Debian/Ubuntu | Fedora/RHEL | Arch |
|---|---|---|---|
| Device mapper | `libdevmapper-dev` | `device-mapper-devel` | `device-mapper` |
| 内核头文件 | `linux-headers-$(uname -r)` | `kernel-devel` | `linux-headers` |
| Gettext | `libgettextpo-dev` | `gettext-runtime` | `gettext` |
| libblkid | `libblkid-dev` | `libblkid-devel` | `util-linux` |
| keyutils（可选） | `libkeyutils-dev` | `keyutils-libs-devel` | `keyutils` |

可选的运行时工具：`clevis`、`partx`。

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

| 选项 | 作用 |
|---|---|
| `CFG_NO_MODULE_KEYRING` | 禁用内核密钥保留服务 |
| `CFG_WINDHAM_ALLOW_ATTACH` | 允许调试器附加到进程 |
| `CFG_NO_ENFORCE_SPEC_MITIGATION` | 跳过 Spectre 漏洞缓解 |
| `CFG_NO_OPT` | 关闭 x86-64 SIMD 优化 |
| `CFG_USE_SWAP` | 允许 KDF 使用交换空间（⚠ 不安全） |
| `CFG_WIPE_MEMORY` | KDF 完成后清零工作内存 |

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
- 64 位平台栈空间约 52 KB + 2×FILENAME_MAX（32 位平台略少）

### 与完整模式的功能对比

| 功能 | 完整模式 (GNU/Linux) | 基础模式 (ISO C11) |
|---|---|---|
| dm-crypt 挂载与读写 | ✓ | ✗ |
| 以 PID 1 运行 | ✓ | ✗ |
| 解析 /etc/windhamtab | ✓ | ✗ |
| 扫描 /proc/partitions 探测设备 | ✓ | ✗ |
| 根据 UUID 定位设备 | ✓ | ✗ |
| 内核密钥保持服务 | ✓ | ✗ |
| 加密头创建/读取/写入 | ✓ | ✓ |
| 添加/删除密钥 | ✓ | ✓ |
| 悬置/恢复 | ✓ | ✓ |
| 备份/恢复/销毁 | ✓ | ✓ |
| 提取主密钥 | ✓ | ✓ |
| Argon2 密钥派生 | ✓ | ✓（没有线程支持时较慢） |
| Unicode 密码输入 | ✓ | 取决于编译器 |
| 辅助数据区读写 | ✓ | ✓ |
| 链接解锁级联 | ✓ | ✗（无 dm-crypt，无 UUID 扫描） |
| 探测单个文件 | ✓ | ✓ |
| gettext 国际化 | ✓ | ✗ |

### 强烈建议的平台特性

ISO C 模式可以在任何符合 C11 的环境下运行，但部分"可选"的主机特性会显著影响功能和安全：

#### 多线程支持（threads.h）

| `__STDC_NO_THREADS__` 的状态 | 实际表现 |
|---|---|
| **未定义**（线程可用） | KDF 并行处理两个密钥池区域，解锁速度约翻倍。随机数使用线程局部状态。 |
| **已定义**（没有线程） | KDF 单线程运行。随机数使用全局状态。功能不受影响，只慢一些。 |

KDF 在解锁时需要探测密钥池的 zone 0 和 zone 1。有线程时两个 zone 并行探测；没有线程时顺序探测。对只注册了少量口令的设备来说影响不大。

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
