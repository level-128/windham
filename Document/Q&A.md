## Quick Q&A

- My system cannot identify the encrypted partition before decrypting. What's going on?
	- Windham is designed to not leave any pre-defined pattern or statical trace to identify its existence. The only
	  way to identify it is to provide a correct key to the correct slot. It is by-design that Windham is undetectable.

&nbsp;

- What is the Master Key?
	- The Master Key is a unique key per device which would grant the holder full access to the encrypted drive. if your
	  master key is compromised, Anyone with a master key can unlock your device. In this case, use `windham RevokeKey *your device* --obliterate`
	  to wipe the header. ALL DATA WILL BE LOST!

&nbsp;

- I'm sure that I provided the correct key-phrase. But I have received an error message:
  `Cannot unlock the target because time or memory limit has reached. This is probably because a wrong key
  has been provided, or your compute resources may be too insufficient to unlock the target created
  by a faster computer....`
	-  If you try to unlock a drive created by a faster
	   computer, the parameter that suits for a fast computer may be beyond the limit by your device. To continue, you can use
	   argument `--max-unlock-memory` (in KiB) or `--max-unlock-time` to expand the estimated compute resource allowance. If
	   it's still not possible to decrypt, use `windham Open *device* --dry-run` to Open a device without mapping it. In this
	   case, the master key will be printed to the console. Then use `windham Open *device* --master-key=*your master key*`
	   to map the device on another computer. Why is windham so strangely designed? You can read this if you're interested:

To defend against brute force attacks, as well as the future attacks with much more computational powerful devices from the
future, when adding a key-phrase, the computer which performs such action will first be benchmarked; then generate
parameters dynamically to perform as many key derivation operations as possible in a preset time limit. such auto-adaption algorithm will
ensure the encryption created in the future will not be relatively weakened by using device-specific parameters. Such parameters could not be embedded in the
header in any way because of ensuring traceless. when a key-phrase is provided, the value from incremental blocks will be
computed from the last KDF iteration via one-time pad for a new parameter, which tells what memory usage and CPU time
will be used for the next step and scales the parameters exponentially by the power of the iteration count.
If a wrong pass-phrase has been provided, then the parameters yield in each step will be wrong during each iteration,
and the program will always be asked to keep calculating using larger and larger parameters (and it will stop after
reaches the threshold).

&nbsp;

- `WARNING: using swap space for Key derivation function. This is potentially insecure because unencrypted swap space
  may provide hints to the master key.` What does this mean?
	- Your operating system may move parts of the data from the memory to your disk. The way that key derivation function
	  works, in this case, it to utilize large memory chunk to prevent brute-force attack from specially crafted hardware.
	  If someone could read this memory, it will provide very useful hints to your master key. You can ignore this message if
	  your swap space is encrypted.

&nbsp;

- What is a key-file?
	- Key-file is a key stored in a file; it uses the full content of the file as the key. To use Key-file as the key, use
	  argument `--key-file=`.

&nbsp;

- When I backed up my header, I found that the header is completely different from the one located on the original disk.
  I could still unlock it with my passwords. So how and why?
	- The header will be randomized into a 'equivalent' form when it has been modified. Each byte in the equivalent header is
	  re-randomized to hide details of each modification. For example, an attacker can make snapshots to the header each time
	  when accessing the victim's hard drive. When comparing each snapshot, the attacker could infer which key slot has been modified
	  to add a new key, and the attacker could focus on brute-forcing that specific key slot to greatly accelerate it. By
	  randomizing the header, and ensuring each randomized header could not be de-randomize unless the operator has a key or master
	  key to the drive (also the attacker can't tell whether two headers are logically equivalent), the threat model mentioned above
	  will be greatly mitigated. However, if you do not have access to the key, use `windham Backup *your device* --no-transform`
	  to back up the header as is.

&nbsp;

- Why I need to provide 