# 参与开发

## 搭建开发环境

```bash
git clone https://github.com/level-128/windham.git
cd windham
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug -DCFG_USE_SWAP=1
cmake --build cmake-build-debug
```

Debug 构建的特点：
- 允许 gdb 等调试器附加（`CFG_WINDHAM_ALLOW_ATTACH`）
- 关闭 Spectre 缓解措施，避免干扰调试（`CFG_NO_ENFORCE_SPEC_MITIGATION`）
- 为方便单测启用交换空间支持（`CFG_USE_SWAP`）

## 运行测试

```bash
# 完整测试套件（需要 root）
sudo python3 tests/run_tests.py --binary cmake-build-debug/windham_debug

# 只跑某一个模块
sudo python3 tests/run_tests.py --binary cmake-build-debug/windham_debug test_link_open

# 以普通用户身份跑不需要 root 的用例
python3 tests/run_tests.py --binary cmake-build-debug/windham_debug --no-elevate test_probe

# 列出所有可用测试
python3 tests/run_tests.py --list
```

测试代码放在 `tests/` 目录，纯 Python 编写。每个 `def test_*()` 就是一个独立用例。运行时会通过 `subprocess` 启动 `windham_debug` 并捕获标准输入、标准输出和标准错误。

### 测试工具函数

`utils.py` 提供了几个常用函数：

- `create_test_device(path)` — 创建 8 MB 稀疏文件用作虚拟磁盘
- `run_windham(args, binary, stdin_text, timeout)` — 启动 windham 子进程并返回 (rc, stdout, stderr)
- `assert_success(args, binary)` / `assert_error(args, binary)` — 断言返回码

### 测试模块一览

| 模块 | 覆盖内容 |
|---|---|
| `test_creation.py` | 新建、打开（dry-run）、错误密码 |
| `test_keymgmt.py` | 添加/删除密钥、加密头重变换、快速添加 |
| `test_keymgmt_variants.py` | 匿名密钥、转为匿名密钥 |
| `test_aux.py` | 辅助数据区添加/查看/删除 |
| `test_aux_variants.py` | 辅助数据区条目类型、跳过辅助数据区标志 |
| `test_link_open.py` | 5 台设备链接级联 + 悬空 UUID 测试 |
| `test_link_open_flags.py` | 8 台设备树，验证 SHORTCUT 剪枝正确性 |
| `test_suspend.py` | 悬置 / 恢复 |
| `test_params.py` | 块大小、加密算法、密钥文件、KDF 参数 |
| `test_probe.py` | 探测目录、探测 Linux 设备、探测不存在设备 |
| `test_backup.py` | 备份 / 恢复 / 销毁加密头 |

## 代码结构总览

```
windham/
├── main.c              # 命令行解析，操作分发
├── frontend.c          # main() 入口、shebang 支持、pid1 初始化
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
│   └── ISOC/           # ISO C11 基础模式
├── library/            # 第三方库
├── include/            # 头文件：windham_const.h、argon2.h、sha256.h 等
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
