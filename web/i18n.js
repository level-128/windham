// Windham Web — frontend i18n. English is the default; keys are the English
// strings themselves, so t() falls back to the key when a language is missing.
// Placeholders use printf-style %s / %d (see tf below).

var I18N = {
  'en': {
    'about_intro': 'Windham Web (Windham Emscripten Port) is an in-browser encrypted disk unlocker.  Upload a <strong style="color:#ccc">FAT32</strong> or <strong style="color:#ccc">exFAT</strong> disk image created by Windham, enter your passphrase, and browse, navigate, and download files — all decryption happens locally in WebAssembly.  No data leaves your machine.',
    'about_create_iso': 'Creating a disk on any ISO&nbsp;C platform: GNU/Linux, macOS, *BSD, Zephyr, HarmonyOS, QNX, Windows, Redox OS and Nuttx.',
    'about_new_disabled': 'Not all supported platform has <code>Windham New</code> enabled. Windham running under FreeRTOS (including ESP-IDF), UEFI EDK II, non-frontend mode or basically all bare-metal systems without an OS has <code>New</code> support absent.',
    'about_create_manual': 'Creating a FAT32 or ExFAT disk manually on GNU/Linux or Linux-kernel based OS with GNU compatible libc (musl …)',
    'about_note': 'Note:',
    'about_note1': '1. it is possible to pass block devices (e.g. /dev/sdx or /dev/nvme0nxpx) as disk image under UNIX. This is not recommended. No test has been made to cover all browser combos for such use case.',
    'about_note2': '2. UEFI GPT partition scheme inside windham image is not supported. However, it is possible to create a protective MBR which contains FAT/exFAT partition range.',
    'about_note3': '3. Windham Web only supports 128/256 bit AES-XTS encryption with block size 512, 1024, 2048 and 4096; dm-crypt compatible XTS scheme, little-endian XTS counter. This is the only supported encryption scheme under ISO C, and it is default under GNU/Linux regardless of the host endianness.',
    'about_note4': '4. UEFI TCG OPAL is <b>NOT</b> compatible with Windham Web and windham ISO C.',
    'backup_desc': 'Download a compact 960 B backup containing a single keyslot. Suitable for paper or QR code recovery.'
  },
  'zh-CN': {
    'Read-only': '只读',
    'Open an encrypted disk image': '打开加密磁盘镜像',
    'Passphrase': '密码',
    'Enter passphrase': '输入密码',
    'Choose & Unlock': '选择并解锁',
    'Drag a .img file here or click to select.': '将 .img 文件拖到此处，或点击选择。',
    'Deriving key...': '正在派生密钥...',
    'About Windham Web': '关于 Windham Web',
    'about_intro': 'Windham Web（Windham Emscripten 移植版）是一款浏览器内的加密磁盘解锁工具。上传由 Windham 创建的 <strong style="color:#ccc">FAT32</strong> 或 <strong style="color:#ccc">exFAT</strong> 磁盘镜像，输入密码即可浏览、导航和下载文件——所有解密均在 WebAssembly 中本地完成，数据不会离开您的设备。',
    'about_create_iso': '在任何 ISO C 平台创建磁盘：GNU/Linux、macOS、*BSD、Zephyr、HarmonyOS、QNX、Windows、Redox OS 和 Nuttx。',
    'about_new_disabled': '并非所有受支持的平台都启用了 <code>Windham New</code>。在 FreeRTOS（包括 ESP-IDF）、UEFI EDK II、非前端模式或任何没有操作系统的裸机系统上运行的 Windham 不具备 <code>New</code> 支持。',
    'about_create_manual': '在 GNU/Linux 或基于 Linux 内核、带 GNU 兼容 libc（musl …）的操作系统上手动创建 FAT32 或 ExFAT 磁盘',
    'about_note': '注意：',
    'about_note1': '1. 在 UNIX 下可以将块设备（如 /dev/sdx 或 /dev/nvme0nxpx）作为磁盘镜像传入。不推荐这样做。尚未对覆盖所有浏览器组合的这种用例进行测试。',
    'about_note2': '2. 不支持 windham 镜像内的 UEFI GPT 分区方案。不过可以创建包含 FAT/exFAT 分区范围的保护性 MBR。',
    'about_note3': '3. Windham Web 仅支持 128/256 位 AES-XTS 加密，块大小为 512、1024、2048 和 4096；dm-crypt 兼容 XTS 方案，小端 XTS 计数器。这是 ISO C 下唯一支持的加密方案，在 GNU/Linux 下无论主机字节序如何都是默认方案。',
    'about_note4': '4. UEFI TCG OPAL <b>不</b>兼容 Windham Web 和 windham ISO C。',
    'Windham is open source —': 'Windham 是开源的 —',
    'give it a star on GitHub': '在 GitHub 上给 Star',
    'Files': '文件',
    'Backup': '备份',
    'Aux': '辅助',
    'Metadata': '元数据',
    'Back': '后退',
    'Forward': '前进',
    'Refresh': '刷新',
    'Select a file to preview. Click ⬇ to download.': '选择文件预览。点击 ⬇ 下载。',
    'Fold Backup': '折叠备份',
    'backup_desc': '下载包含单个密钥槽的紧凑 960 B 备份。适合纸质或二维码恢复。',
    '💾 Download fold backup (.bu)': '💾 下载折叠备份 (.bu)',
    '📱 Show QR Code': '📱 显示二维码',
    'Auxiliary Entries': '辅助条目',
    'Header Metadata': '头部元数据',
    'Field': '字段',
    'Value': '值',
    'Drop disk image to open': '拖入磁盘镜像以打开',
    'Error': '错误',
    'Dismiss': '关闭',
    'Browser not supported': '浏览器不受支持',
    'Your browser is missing required APIs': '您的浏览器缺少必要的 API',
    'Use Chrome 86+ or Edge 86+ for full support.': '如需完整支持，请使用 Chrome 86+ 或 Edge 86+。',
    'Unknown error': '未知错误',
    'Worker Crashed': 'Worker 崩溃',
    'Worker Error': 'Worker 错误',
    'cd Failed': 'cd 失败',
    'ls Failed': 'ls 失败',
    'Export': '导出',
    'Export Failed': '导出失败',
    'Downloading...': '正在下载...',
    'Loading preview...': '正在加载预览...',
    'File is empty.': '文件为空。',
    'Showing first %s of the file.': '仅显示文件前 %s。',
    'File too large to preview (max %s).': '文件过大，无法预览（上限 %s）。',
    'Download': '下载',
    'Backup Failed': '备份失败',
    'QR Failed': '二维码失败',
    'Aux Failed': '辅助失败',
    'Metadata Failed': '元数据失败',
    'Worker not ready': 'Worker 未就绪',
    'Worker has not loaded yet.': 'Worker 尚未加载。',
    'Unlock Failed': '解锁失败',
    'Timeout': '超时',
    'Could not obtain master key.': '无法获取主密钥。',
    'Master key derivation timed out.': '主密钥派生超时。',
    'Unlock took too long.': '解锁耗时过长。',
    'No passphrase available. Re-open the disk first.': '没有可用密码。请先重新打开磁盘。',
    'No passphrase available.': '没有可用密码。',
    'Exiting shell...': '正在退出 Shell...',
    'Creating fold backup...': '正在创建折叠备份...',
    'Reading backup...': '正在读取备份...',
    'Backup downloaded. Remounting...': '备份已下载。正在重新挂载...',
    'Backup complete.': '备份完成。',
    'Backup failed: %s': '备份失败：%s',
    'Generating QR code...': '正在生成二维码...',
    'Reading QR image...': '正在读取二维码图像...',
    'QR code generated.': '二维码已生成。',
    'QR failed: %s': '二维码失败：%s',
    'Loading...': '加载中...',
    'No aux entries found.': '未找到辅助条目。',
    'Failed: %s': '失败：%s',
    'No master key available.': '没有可用的主密钥。',
    'Remounting...': '正在重新挂载...',
    'Mounting filesystem...': '正在挂载文件系统...',
    'Failed.': '失败。',
    'Timeout.': '超时。',
    '%d dirs, %d files': '%d 个目录，%d 个文件',
    'Slot': '槽位',
    'Level': '等级',
    'Memory': '内存',
    'Zone': '区域',
    'Identifier': '标识符',
    'Disk images': '磁盘镜像'
  }
};

var _lang = 'en';

function detectLang() {
    var nav = (navigator.language || navigator.userLanguage || 'en').toLowerCase();
    if (nav.indexOf('zh') === 0) return 'zh-CN';
    return 'en';
}

function t(key) {
    var d = I18N[_lang];
    return (d && d[key] !== undefined) ? d[key] : key;
}

function tf(key) {
    var s = t(key);
    var args = Array.prototype.slice.call(arguments, 1);
    return s.replace(/%[sd]/g, function() { return args.length ? args.shift() : ''; });
}

function applyI18n() {
    document.querySelectorAll('[data-i18n]').forEach(function(el) {
        el.textContent = t(el.getAttribute('data-i18n'));
    });
    document.querySelectorAll('[data-i18n-html]').forEach(function(el) {
        el.innerHTML = t(el.getAttribute('data-i18n-html'));
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(function(el) {
        el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
    });
    document.querySelectorAll('[data-i18n-title]').forEach(function(el) {
        el.title = t(el.getAttribute('data-i18n-title'));
    });
}

function setLang(lang) {
    _lang = lang;
    applyI18n();
}
