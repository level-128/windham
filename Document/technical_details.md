# technical details

Memory layout of the header:

```
Address                                              Layout
                            +---------------------------------------------------------+
0x00                        | head (16 bytes)                                         |      <-- ramdom data
                            +---------------------------------------------------------+
0x10                        | Metadata                                                | ---+
                            |   +-----------------------------------------------------+    |
                            |   | key_slot_is_used (KEY_SLOT_COUNT bytes)             |    |
                            |   +-----------------------------------------------------+    |
                            |   | all_key_mask (KEY_SLOT_COUNT x HASHLEN bytes)       |    |
                            |   +-----------------------------------------------------+    |
                            |   | payload_offset (4 bytes)                            |    |
                            |   +-----------------------------------------------------+    | --- Encrypted
                            |   | header_size (4 bytes)                               |    |
                            |   +-----------------------------------------------------+    |
                            |   | enc_type (32 bytes)                                 |    |
                            |   +-----------------------------------------------------+    |
                            |   | check_key_magic_number (8 bytes)                    |    |
                            |   +-----------------------------------------------------+    |
                            |                         ...                             |    |
                            | AES_align (padding to a multiple of AES_BLOCKLEN)       | ---+ <-- ramdom data
                            |                         ...                             |
                            +---------------------------------------------------------+
(number + AES_BLOCKLEN - 1) |                                                         |
/ AES_BLOCKLEN              | master_key_mask (HASHLEN bytes)                         |
* AES_BLOCKLEN + 0x10       |                                                         |
                            +---------------------------------------------------------+
                            | keys                                                    |
                            |   +-----------------------------------------------------+
                            |   | hash_salt (HASHLEN bytes)                           |
                            |   +-----------------------------------------------------+
                            |   | len_exp (KEY_SLOT_EXP_MAX x 4 bytes)                |
                            |   +-----------------------------------------------------+
                            |   | key_mask (HASHLEN bytes)                            |
                            |   +-----------------------------------------------------+
                            |                         ...                             |
                            |   (repeat KEY_SLOT_COUNT times)                         |
                            |                         ...                             |
                            +---------------------------------------------------------+
data.Metadata.header_size   |                         ...                             |
                            |              Padding to disk sector size                |      <-- ramdom data
                            |                         ...                             |
                            +---------------------------------------------------------+
data.Metadata.payload_offset|                         ...                             |
                            |                    encrypted data                       |
                            |                         ...                             |
                            |                         ...                             |
```