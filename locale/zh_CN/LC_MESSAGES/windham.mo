��          <      \       p   �   q   K  (  9  t  5  �  �   �  @  �  �  �                   Common options:
	--no-admin: forfeit checking root privileges, may produce undefined behaviour. 
	--yes: do not ask for explicit confirmation for potentially destructive operations.
 Unlock options:
	--key <characters>: key input as argument, instead of asking in the terminal.
	--key-file <location>: key input as key file. The key file will be read as key (exclude EOF character). Option '--key' and '--key-file' and '--target-slot' are mutually exclusive
	--master-key <characters>: using master key to unlock.
	--unlock-slot <int>: choose the slot to unlock; Other slots are ignored.
	--max-unlock-memory <int>: The total maximum available memory to use (KiB) available for decryption. 
	--max-unlock-time <float>: the suggested total time (sec) to compute the key.
 usage: "windham <action> <target>"
possible actions are:  'Open'  'Close'  'New'  'AddKey'  'RevokeKey' and 'Backup'

Type "windham Help <action>" to view specific help text for each action.

pre-compiled arguments. These arguments serve an informative purpose; changing them may render your
device inaccessible.
 Project-Id-Version: level 128
Report-Msgid-Bugs-To: 
PO-Revision-Date: 2023-10-16 01:01-0400
Last-Translator: level-128 <level-128@gmx.com>
Language-Team: Chinese (simplified) <i18n-zh@googlegroups.com>
Language: zh_CN
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
 常见选项：
	--no-admin：放弃检查root权限，可能产生未定义的行为。
	--yes：不要求对可能具破坏性的操作给予明确确认。
 解锁选项：
	--key <字符>：作为参数输入密钥，而非在终端中输入。
	--key-file <位置>：将密钥文件作为输入。密钥文件将被读取为密钥（不包括EOF字符）。‘--key’、‘--key-file’及‘--target-slot’三选项互斥
	--master-key <字符>：使用主密钥进行解锁。
	--unlock-slot <整数>：选择要解锁的插槽；其它插槽将被忽略。
	--max-unlock-memory <整数>：用于解密的可用最大内存总量（单位为KiB）。
	--max-unlock-time <浮点数>：计算密钥的建议总时间（秒）。
 用法："windham <操作> <目标>"
可能的操作包括：'Open'（打开） 'Close'（关闭） 'New'（新建） 'AddKey'（添加密钥） 'RevokeKey'（撤销密钥）以及'Backup'（备份）

键入"windham Help <操作>"来查看每个操作的具体帮助文本。

预编译参数。这些参数具有信息性目的；更改它们可能会导致您的
设备无法访问。
 