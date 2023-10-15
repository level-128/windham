# Windham Principle Explanation and Architecture Analysis

Windham, as a block encryption implementation, defends against unauthorized offline access to devices. This means that for attackers, without obtaining the key, they cannot access storage devices offline. In theory, this only requires mapping after encrypting every byte of the entire hard disk (which is what `dm-crypt` does). However, for ordinary users, remembering a high-entropy key of at least 128 bits (often 192 or 256 bits) is almost impractical (and users cannot easily enter non-printable characters), and it is extremely dangerous to directly use printable characters to set keys without key iteration functions, exposing them to brute-force or dictionary-based attacks. Currently, AES series encryption (chosen due to computational efficiency compromises) is susceptible to related key attacks, meaning that password management and derivation must be integrated into the encryption scheme. This is the purpose of Windham's existence.

The presence of an encrypted partition metadata header allows users to register multiple user-friendly passwords to address the aforementioned issues, and to derive the same hard disk key via stored vectors. To defend against brute-force attacks, key derivation uses a memory-hard key derivation function, and its parameters are determined by the computer performing the encryption. This means that for brute force attacks, the runtime and space constants added to the defender over the attacker are determined by the computer performing the encryption operation. This ensures that the strength of the Windham encrypted partition will improve with the advancement of future computers. Considering that the key space of AES256 is already so large that brute-force decryption is impossible for classical computers, the above description holds for the foreseeable future.

Windham's design not only meets the above requirements but also offers plausible deniability. Windham's threat model includes:

- When an attacker obtains an offline storage hard disk, the attacker cannot access the hard disk, nor can they use known information on the disk to confirm the existence of an encrypted partition. In other words, the Windham encrypted partition has plausible deniability.
- When an attacker can obtain multiple snapshots of the encrypted hard disk, they are prevented from inferring the operations they performed on the encrypted partition from the metadata header (e.g., how many passwords were used, which/how many key slots stored passwords) to slow down brute-force attacks.
- Attackers cannot accelerate password brute-forcing through GPUs, find it difficult to design ASICs for a significant advantage, and cannot use time-memory tradeoff attacks to:
  - Reduce memory size dependence
  - Use large, faster caches to significantly speed up key derivation.

Also, the most important point: user-friendly operation.

Currently, many hard disk encryption schemes exist on the Linux platform: LUKS (through cryptsetup) and VeraCrypt. The former is the de facto encryption standard on the Linux platform. It surpasses Windham in terms of flexibility, such as key slot count and key derivation function selection (Windham's random metadata header cannot achieve these features). However, Windham has advantages in metadata header tamper resistance, plausible deniability encryption, and resistance to low-entropy password brute-forcing. Compared to VeraCrypt, Windham supports memory-hard key derivation functions and automatic key derivation parameter selection.

# Metadata Header Design

Windham's metadata header cannot be distinguished from cryptographically secure random numbers. Additionally, any changes to the metadata header are "atomic"; in other words, every modification operation on the encrypted metadata header produces a completely distinct "equivalent" metadata header from the previous one. Without holding one of the registered passwords or the master key, it's impossible for the new metadata header to:

- Determine if it is equivalent to another metadata header (i.e., they have registered the same passwords and used the same master key).
 - Ascertain if it was derived from modifying another metadata header.

At the same time, the metadata header ensures:

- Without possessing the master key and any of the passwords, attackers cannot extract any information from the metadata header, nor can they confirm that the data is a metadata header (unless the initial 16 bytes are marked).
 - Attackers cannot modify the master key or registered passwords by changing the metadata, but modifying certain sections can render specific password slots ineffective. This action is referred to as "Key Revoke". Any revoking operation made without unlocking will alert the user during partition unlocking. Any other arbitrary changes to the rest of the sections will render the entire metadata header completely ineffective (i.e., it's impossible to retrieve the final disk key).

The above encapsulates the design goals of Windham. The realization of these objectives can be inferred from the layout of the metadata header.


```
Address                                              Layout
                            +---------------------------------------------------------+
0x00                        | head (16 bytes)                                         |      <-- ramdom data
                            +---------------------------------------------------------+
0x10                        | Metadata                                                | ---+
                            |   +-----------------------------------------------------+    |
                            |   | inited_key (KEY_SLOT_COUNT x HASHLEN bytes)         |    |
                            |   +-----------------------------------------------------+    |
                            |   | all_key_mask (KEY_SLOT_COUNT x HASHLEN bytes)       |    |
                            |   +-----------------------------------------------------+    |
                            |   | key_slot_is_used (KEY_SLOT_COUNT bytes)             |    |
                            |   +-----------------------------------------------------+    |     
                            |   | disk_key_mask (HASHLEN bytes)                       |    | Encrypted using
                            |   +-----------------------------------------------------+    | master key and
                            |   | start_sector (4 bytes)                              |    | master_key_mask
                            |   +-----------------------------------------------------+    | 
                            |   | end_sector (4 bytes)                                |    |
                            |   +-----------------------------------------------------+    |
                            |   | enc_type (32 bytes)                                 |    |
                            |   +-----------------------------------------------------+    |
                            |   | check_key_magic_number (8 bytes)                    |    |
                            |   +-----------------------------------------------------+    |
                            |                         ...                             |    |
                            | AES_align (padding to a multiple of AES_BLOCKLEN)       |    | <-- ramdom data
                            |                         ...                             | ---+
                            +---------------------------------------------------------+
(number + AES_BLOCKLEN - 1) |                                                         |
/ AES_BLOCKLEN              | master_key_mask (HASHLEN bytes)                         |      <-- ramdom data
* AES_BLOCKLEN + 0x10       |                                                         |
                            +---------------------------------------------------------+
                            | keys                                                    | ---+
                            |   +-----------------------------------------------------+    |
                            |   | hash_salt (HASHLEN bytes)                           |    |
                            |   +-----------------------------------------------------+    |
                            |   | len_exp (KEY_SLOT_EXP_MAX x 4 bytes)                |    | Encrypted using
                            |   +-----------------------------------------------------+    | inited_key and
                            |   | key_mask (HASHLEN bytes)                            |    | master_key_mask
                            |   +-----------------------------------------------------+    |
                            |                         ...                             |    |
                            |   (repeat KEY_SLOT_COUNT times)                         |    |
                            |                         ...                             | ---+
                            +---------------------------------------------------------+
data.Metadata.header_size   |                         ...                             |
                            |              Padding to disk sector size                |
                            |                         ...                             |
                            +---------------------------------------------------------+
data.Metadata.payload_offset|                         ...                             |
                            |                    encrypted data                       |
                            |                         ...                             |
                            |                         ...                             |
```

**_Diagram 1: Memory layout of windham's metadata header_**

In this diagram, both `Metadata` and `Keys` are encrypted, representing the data section and key slots respectively. Each encryption header has `KEY_SLOT_COUNT` slots (default: 6; changes require recompilation). They both use parts of `master_key_mask` as the initial vector. Subsequently, for each key slot, the initial key obtained from passing the user-entered password through SHA256 is XOR'd with `master_key_mask` to be used as the password for each `Keys`. AES-CBC is then employed to decrypt each `Keys`, followed by key derivation (details of which will be discussed in the next chapter). The data decrypted from each key slot is cryptographically random.

## Tamper 

# TODO
