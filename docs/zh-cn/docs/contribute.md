# 参与开发

## 搭建开发环境

```bash
git clone https://github.com/level-128/windham.git
cd windham
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug -DCFG_USE_SWAP=1
cmake --build cmake-build-debug
```

Debug 构建的特点：
- 允许 gdb 等调试器附加（`WINDHAM_NO_DISABLE_ATTACH`）
- 关闭 Spectre 缓解措施，避免干扰调试（`WINDHAM_NO_ENFORCE_SPEC_MITIGATION`）
- 为方便单测启用交换空间支持（`CFG_USE_SWAP`）

## 运行测试

测试套件按目标平台分为两块：

- **ISO C 基准块**（`REQUIRES = "isoc"` 或 `"any"`）：对直接编译出的 ISO C
  二进制运行。纯用户态——普通文件、无需 root、无内核 device-mapper。
  这是必须在所有平台上通过的基线。
- **GNU/Linux 后端块**（`REQUIRES = "gnu-linux"`）：测试内核 dm-crypt 后端
  （loop 设备、`/dev/mapper`、级联解锁）。需要 root 和 CMake 构建。

运行器会自动检测二进制的目标平台（可用 `--platform=isoc|gnu-linux` 强制指定），
并跳过 `REQUIRES` 不匹配的测试。

### ISO C 基准块

直接编译 `frontend.c`（无需构建系统），把二进制路径传给运行器：

```bash
cc -std=c11 -O2 frontend.c -lm -o windham_isoc

# 完整 ISOC 套件——无需 root
python3 tests/run_tests.py --binary ./windham_isoc

# 只跑某一个模块
python3 tests/run_tests.py --binary ./windham_isoc test_aux
```

平台无关测试中的真实 `Open` 都带 `--print-encryption`（no-op print 驱动），
保证在没有内核 mapper 时行为一致。

### GNU/Linux 后端块

使用 Test 构建类型，它会在编译测试二进制的同时找到 Python 解释器：

```bash
cmake -B cmake-build-test -DCMAKE_BUILD_TYPE=Test -DCFG_USE_SWAP=TRUE
cmake --build cmake-build-test
```

通过 `check` 目标运行，或手动运行：

```bash
cmake --build cmake-build-test --target check

# 完整测试套件（自动通过 pkexec 提权）
python3 tests/run_tests.py --binary cmake-build-test/windham_test

# 只跑某一个模块
python3 tests/run_tests.py --binary cmake-build-test/windham_test test_link_open

# 以普通用户身份跑不需要 root 的用例
python3 tests/run_tests.py --binary cmake-build-test/windham_test --no-elevate test_probe

# 列出所有运行器选项
python3 tests/run_tests.py --binary cmake-build-test/windham_test --no-elevate --help
```

测试代码放在 `tests/` 目录，纯 Python 编写。每个 `def test_*()` 就是一个独立用例。运行时会通过 `subprocess` 启动二进制并捕获标准输入、标准输出和标准错误。

### 测试工具函数

`utils.py` 提供了几个常用函数：

- `create_test_device(path)` — 创建 8 MB 稀疏文件用作虚拟磁盘
- `run_windham(args, binary, stdin_text, timeout)` — 启动 windham 子进程并返回 (rc, stdout, stderr)
- `assert_success(args, binary)` / `assert_error(args, binary)` — 断言返回码

平台门控：模块级 `REQUIRES` 属性门控整个文件；函数属性（`test_x.requires = "gnu-linux"`）
门控单个测试；`"any"` 表示两个块都跑。仅 `gnu-linux` 块会尝试 pkexec 提权。

### 测试模块一览

| 模块 | 块 | 覆盖内容 |
|---|---|---|
| `test_creation.py` | any | 新建、打开（dry-run）、错误密码 |
| `test_keymgmt.py` | any | 添加/删除密钥、加密头重变换、快速添加 |
| `test_keymgmt_variants.py` | any | 匿名密钥、转为匿名密钥 |
| `test_aux.py` | any | 辅助数据区添加/查看/删除；`--aux-probe --aux-exec`；`--master-key` 公开条目；DelKey 级联清理辅助条目；LINK_OPEN 条目生命周期；`--aux-rm` |
| `test_aux_variants.py` | any | 辅助数据区条目类型、跳过辅助数据区标志 |
| `test_shell_exec.py` | any + 一个 gnu-linux 测试 | SHELL 命令显式执行（`--aux-exec`）、BLCKOPEN、单设备 `@` 替换；级联 `@` 替换（仅 gnu-linux） |
| `test_suspend.py` | any | 悬置 / 恢复 |
| `test_params.py` | any | 块大小、加密算法、密钥文件、KDF 参数；`Bench`；`--show-master-key`；负面用例（不存在的设备、`UUID=` 前缀）；关闭未映射名称 |
| `test_probe.py` | any | 探测目录、探测 Linux 设备、探测不存在设备 |
| `test_backup.py` | any | 备份 / 销毁；备份→销毁→恢复往返（辅助条目存活）；fold 备份/恢复往返；QR 备份（终端 + BMP） |
| `test_decrypt.py` | any + 一个 gnu-linux 测试 | 用户态解密往返（`--create-exfat` → `--decrypt` → exFAT 签名）；dm-crypt 写路径端到端（仅 gnu-linux） |
| `test_fat.py` | any + 一个 gnu-linux 测试 | ff 驱动 FatFs Shell（stdin 交互）；dm-crypt mapper 超级块校验（仅 gnu-linux） |
| `test_link_open.py` | gnu-linux | 5 台设备链接级联 + 悬空 UUID 测试 |
| `test_link_open_flags.py` | gnu-linux | 8 台设备树，验证 SHORTCUT 剪枝正确性 |

## 代码结构总览

```
windham/
├── windham_config.h     # 构建配置（默认值与功能开关）
├── main.c              # 命令行解析，操作分发
├── frontend.c          # main() 入口、平台初始化
├── backend/            # 各操作的实现
│   ├── bklibopen.c     # Open 及链接解锁级联
│   ├── bklibcreat.c    # New（新建）
│   ├── bklibkey.c      # AddKey / DelKey
│   ├── bklibact.c      # Suspend / Resume / Destroy / Backup / Restore
│   ├── bklibaux.c      # 辅助数据区：增删查 + 链接添加
│   ├── bklibprobe.c    # 探测 Windham 分区
│   └── bklibhelp.c     # 帮助文本
├── libsrc/             # 核心逻辑
│   ├── enclib.c        # 加密、KDF、密钥派生
│   ├── auxlib.c        # 辅助数据区结构与序列化
│   ├── libkdf.c        # Argon2id 包装、内存边界
│   ├── chkhead.c       # 加密头随机性统计检测
│   ├── probelib.c      # 单个设备探测
│   └── srclib.c        # 公共工具宏
├── libplat/            # 平台相关
│   ├── GNU_Linux/      # 完整模式：dm-crypt、内核密钥环、loop ioctl
│   ├── ISOC/           # ISO C11 基础模式
│   └── WASI/           # Emscripten / WebAssembly
├── driver/             # 驱动注册表 + dm-mapper / FatFs Shell / 解密
├── library/            # 第三方库
├── include/            # 头文件：windham_const.h、argon2.h、sha256.h 等
├── web/                # Emscripten Web 应用（index.html、worker.js）
└── tests/              # Python 测试套件
```

## 提交信息风格

```
feat: 简述        # 新功能
fix: 简述         # Bug 修复
docs: 简述        # 纯文档变更
refactor: 简述    # 代码重构
test: 简述        # 测试变更
```
