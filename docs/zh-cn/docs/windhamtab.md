# /etc/windhamtab 与开机自动解锁

Windham 支持 `/etc/windhamtab`，一份类似于 systemd `/etc/crypttab` 的配置文件，用于描述开机时需要自动解锁的加密设备。

## 文件格式

首次运行以下命令会自动生成模板文件：

```bash
sudo windham Open TAB
```

每行描述一个设备，格式如下：

```
<设备>  <映射名称>  <密钥方式>  <选项>  <pass>
```

`<设备>` 字段必须以 `DEV=`、`PATH=` 或 `UUID=` 前缀开头。`<pass>` 是控制解锁
顺序的纯数字（0–65535），可省略（视为 0）。示例条目：

```
DEV=/dev/sda                    root  ASK      readonly
UUID=abc-def-123                home  KEYFILE=/etc/keys/home.key
DEV=/dev/nvme0n1p3              data  CLEVIS=/etc/clevis/data.jwe  nofail
DEV=/dev/sdb                    swap  ASK      allow-discards,no-read-workqueue
```

### 密钥方式

| 方式 | 说明 |
|---|---|
| `ASK` | 交互式提示输入密码 |
| `KEYFILE=<文件路径>` | 从文件读取密码 |
| `CLEVIS=<JWE 文件路径>` | 调用 Clevis 解密（支持 TPM、Tang 等多种 Pin） |

### 可用选项（逗号分隔）

`readonly`、`allow-discards`、`no-read-workqueue`、`no-write-workqueue`、
`nofail`、`systemd`、`no-map-partition`、`unlock-slot=<序号>`、
`max-unlock-memory=<KiB>`、`max-unlock-time=<秒>`

### Pass 排序控制

末尾的 `<pass>` 列（纯数字）控制解锁先后顺序，序号越小的越先处理。如需单独
执行某一个 pass，可在命令行加 `--windhamtab-pass=<序号>`：

```
DEV=/dev/sda root ASK readonly 1
DEV=/dev/sdb home ASK readonly 2
```

---

## Clevis + TPM 2.0 集成

### 生成并密封随机密钥

```bash
sudo windham AddKey /dev/sda --generate-random-key \
  | sudo clevis encrypt tpm2 '{}' > /etc/clevis/root.jwe
```

上面的命令会随机生成一个 32 字节的密钥，输出到标准输出，再通过管道送给 `clevis encrypt` 用 TPM 2.0 密封，最终写入 JWE 文件。

### 开机时通过 Clevis 解密

在 `/etc/windhamtab` 中这样写：

```
DEV=/dev/sda root CLEVIS=/etc/clevis/root.jwe
```

或者直接在命令行使用：

```bash
cat /etc/clevis/root.jwe | sudo clevis decrypt tpm2 '{}' \
  | sudo windham Open /dev/sda --keystdin
```

### 配合 Tang 服务器（网络解锁）

```bash
sudo windham AddKey /dev/sda --generate-random-key \
  | sudo clevis encrypt tang '{"url":"http://tang-server"}' > /etc/clevis/root.jwe
```

---

## 与 systemd 配合

在 systemd 服务中运行时，终端交互式密码输入不可用。此时在 windhamtab 中添加 `systemd` 选项：

```
DEV=/dev/sda root ASK systemd
```

添加该选项后，Windham 会改用 `systemd-ask-password` 弹出密码提示，并可与 Plymouth 开机画面集成。

---

## 编写 init 服务实现开机解锁

编写一个在 `local-fs.target` 之前运行的 systemd 单元：

```ini
# /etc/systemd/system/windham-open.service
[Unit]
Description=Windham 设备解锁
DefaultDependencies=no
Before=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/windham Open TAB
RemainAfterExit=yes

[Install]
WantedBy=local-fs.target
```

然后 `systemctl enable windham-open.service` 即可。
