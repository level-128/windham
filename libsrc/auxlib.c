#ifndef INCL_AUXLIB
#define INCL_AUXLIB

#include "../include/windham_const.h"
#include <string.h>
#include <stdlib.h>
#include <uchar.h>
#include <float.h>
#include <locale.h>

#include "../include/aes.h"
#include "endian.c"
#include "srclib.c"
#include "enclib.c"


const uint8_t aux_zone_terminator_magic[8] = {'l', 'e', 'v', 'e', 'l', '1', '2', '8'};


enum AuxTypes{
    NMOBJ_AUX_TYPE_PLAINTEXT = 0,
    NMOBJ_AUX_TYPE_SHELL = 1,
    NMOBJ_AUX_TYPE_LINK_OPEN = 2,
};


#define AUX_PROTECTION_ZERO_SIZE 16 // 128 bits protection zero

// On-disk AuxSlot layout:
//   uint16_t size              (2 bytes, little-endian)
//   uint8_t  iv[AES_BLOCKLEN]  (16 bytes, per-slot IV for AES-CBC)
//   uint8_t  encrypted_payload[] (AES-CBC encrypted: content || protection_zero)
// Protection zero (last 16 bytes of plaintext) is not counted in content_size.
// If key is all-zero, no encryption is applied (plaintext stored directly).
typedef struct {
    alignas(2) uint16_t size; // little endian
    alignas(1) uint8_t iv[AES_BLOCKLEN]; // per-slot IV for AES-CBC encryption
    alignas(4) char32_t content_char32_be[]; // flexible: encrypted payload (content + protection zero)
} AuxSlot;


const int AUX_CONTENT_SHELL_FLG_STOP_EXEC_NEXT_IF_SUCC = 1;
const int AUX_CONTENT_SHELL_FLG_EXEC_NEXT_IF_FAIL = 2;



typedef struct {
    alignas(1) uint8_t aux_type;
    alignas(1) uint8_t prio; // lower prio means run first
    alignas(4) uint8_t flags;
    alignas(2) uint16_t timeout; // little endian, sec.
    alignas(4) uint16_t command_len; // little endian
    alignas(4) char32_t command[];
} AuxContentShell;


const int AUX_CONTENT_LINK_OPEN_FLG_STOP_EXEC_NEXT_IF_SUCC = 4;

typedef struct {
    alignas(1) uint8_t aux_type;
    alignas(1) uint8_t flags;
    alignas(1) uint8_t target_unlock_level; // kdf iter level for this key to unlock
    alignas(1) uint8_t prio; // lower prio means link first
    alignas(4) uint8_t target_uuid[16];
    alignas(2) uint16_t target_key_len; // little endian
    alignas(4) char32_t target_key[];
} AuxContentLinkOpen;



// Helper: check if key is all-zero (meaning "no encryption / public entry")
static bool is_key_zero(const uint8_t key[HASHLEN]) {
    return memcmp(key, (const uint8_t[HASHLEN]){0}, HASHLEN) == 0;
}


// Helper: round up to next multiple of AES_BLOCKLEN (for CBC padding)
static size_t round_up_aes_blocklen(size_t len) {
    return (len + AES_BLOCKLEN - 1) / AES_BLOCKLEN * AES_BLOCKLEN;
}


// Helper: decrypt the payload of an aux slot and verify protection zero.
// Returns true if the protection zero check passes (key is correct), false otherwise.
// payload points to the encrypted payload, payload_len is its length.
// iv is the per-slot IV. key is the raw key (will be hashed with SHA-256 for AES key).
static bool decrypt_and_verify_aux_payload(
    const uint8_t payload[], size_t payload_len,
    const uint8_t iv[AES_BLOCKLEN],
    const uint8_t key[HASHLEN])
{
    // Verify protection zero: last AUX_PROTECTION_ZERO_SIZE bytes must be all zero
    if (payload_len < AUX_PROTECTION_ZERO_SIZE) {
        return false;
    }

    uint8_t *plaintext = malloc(payload_len);
    if (!plaintext) return false;
    memcpy(plaintext, payload, payload_len);

    if (!is_key_zero(key)) {
        uint8_t aes_key[HASHLEN];
        sha256_digest_all(key, HASHLEN, aes_key);
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, aes_key, iv);
        AES_CBC_decrypt_buffer(&ctx, plaintext, payload_len);
    }

    bool ok = true;
    for (int i = 0; i < AUX_PROTECTION_ZERO_SIZE; i++) {
        if (plaintext[payload_len - AUX_PROTECTION_ZERO_SIZE + i] != 0) {
            ok = false;
            break;
        }
    }
    free(plaintext);
    return ok;
}


void init_aux_zone(uint8_t aux_zone[], size_t aux_zone_size) {
    if (aux_zone_size == 0) {
        return;
    }
    memset( aux_zone, 0, aux_zone_size);
    memcpy(&aux_zone[aux_zone_size - sizeof(aux_zone_terminator_magic)],
        aux_zone_terminator_magic,
        sizeof(aux_zone_terminator_magic));
}

void encrypt_aux_zone(uint8_t aux_zone[], size_t aux_zone_size, uint8_t aux_zone_key[HASHLEN], uint8_t master_key_mask_as_iv[HASHLEN]) {
    if (aux_zone == NULL) {
        assert(aux_zone_size == 0 && "Aux zone size must equal to 0 if aux zone is NULL");
    }
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aux_zone_key, master_key_mask_as_iv);
    AES_CBC_encrypt_buffer(&ctx, aux_zone, aux_zone_size);
}

void encrypt_aux_zone_using_master_key(Data * data,
    uint8_t aux_zone[], size_t aux_zone_size, const uint8_t master_key[HASHLEN]) {
    if (aux_zone_size == 0) {
        return;
    }
    if (memcmp(&aux_zone[aux_zone_size - sizeof(aux_zone_terminator_magic)],
        aux_zone_terminator_magic,
        sizeof(aux_zone_terminator_magic)) != 0) {
        assert(false);
    }
    uint8_t aux_key[HASHLEN];
    get_metadata_key_or_disk_key_from_master_key(master_key, data->metadata.aux_key_mask, data->uuid_and_salt, aux_key, HASHLEN);
    encrypt_aux_zone(aux_zone, aux_zone_size, aux_key, data->master_key_mask);
}

bool decrypt_aux_zone(uint8_t aux_zone[], size_t aux_zone_size, uint8_t aux_zone_key[HASHLEN], uint8_t master_key_mask_as_iv[HASHLEN]) {
    if (aux_zone_size == 0) {
        return true;
    }
    if (aux_zone == NULL) {
        return false;
    }
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aux_zone_key, master_key_mask_as_iv);
    AES_CBC_decrypt_buffer(&ctx, aux_zone, aux_zone_size);
    return memcmp(&aux_zone[aux_zone_size - sizeof(aux_zone_terminator_magic)],
        aux_zone_terminator_magic,
        sizeof(aux_zone_terminator_magic)) == 0;
}

bool decrypt_aux_zone_using_master_key(Data * data,
    uint8_t aux_zone[], size_t aux_zone_size, const uint8_t master_key[HASHLEN]) {
    if (aux_zone_size == 0) {
        return true;
    }
    uint8_t aux_key[HASHLEN];
    get_metadata_key_or_disk_key_from_master_key(master_key, data->metadata.aux_key_mask, data->uuid_and_salt, aux_key, HASHLEN);
    return decrypt_aux_zone(aux_zone, aux_zone_size, aux_key, data->master_key_mask);
}


// Helper: read aux zone from device into a malloc'd buffer.
// Returns the buffer (caller must free), or NULL if aux_sector_size == 0.
static uint8_t * read_aux_zone_from_device(const char * device, const Data * data, size_t * out_aux_zone_size) {
    if (data->metadata.aux_sector_size == 0) {
        *out_aux_zone_size = 0;
        return NULL;
    }

    size_t aux_zone_size = (size_t)data->metadata.aux_sector_size * 512;
    *out_aux_zone_size = aux_zone_size;

    uint8_t * aux_zone = malloc(aux_zone_size);
    if (aux_zone == NULL) {
        print_error(_("Failed to allocate memory for aux zone."));
    }

    int64_t aux_offset = (int64_t)data->metadata.start_aux_sector * 512;
    operate_aux_zone_on_device(aux_zone, aux_zone_size, device, aux_offset, true);
    return aux_zone;
}


// Helper: write aux zone back to device.
static void write_aux_zone_to_device(const char * device, const Data * data, uint8_t * aux_zone, size_t aux_zone_size) {
    if (aux_zone_size == 0 || aux_zone == NULL) {
        return;
    }

    int64_t aux_offset = (int64_t)data->metadata.start_aux_sector * 512;
    operate_aux_zone_on_device(aux_zone, aux_zone_size, device, aux_offset, false);
}



AuxSlot * probe_aux_from_aux_zone(const uint8_t aux_zone[], size_t aux_zone_size, uint32_t * pointer, const uint8_t key[HASHLEN], bool * out_is_public, uint32_t * out_offset) {
    if (aux_zone_size == 0) {
        return NULL;
    }

    // the last few bytes are terminators.
    aux_zone_size -= sizeof(aux_zone_terminator_magic);

    if (*pointer >= aux_zone_size) {
        WINDHAM_UNREACHABLE // don't check here, crash.
    }

    bool key_zero = is_key_zero(key);

    while (true) {
        uint16_t cur_size;
        memcpy(&cur_size, &aux_zone[*pointer], sizeof(cur_size));
        cur_size = le16toh(cur_size);

        if (cur_size == 0) {
            return NULL; // end of slots
        }
        if (cur_size > aux_zone_size - *pointer - sizeof(uint16_t)) { // need space for EMOBJ_AUX_END
            print_error(_("corrupted aux zone: slot size exceeds remaining space"));
        }

        // Layout: size(2) + iv(16) + encrypted_payload(...)
        size_t header_size = offsetof(AuxSlot, content_char32_be);
        if (cur_size < header_size + AUX_PROTECTION_ZERO_SIZE) {
            // Slot too small to contain header + protection zero
            *pointer += cur_size;
            continue;
        }

        const uint8_t *slot_iv = &aux_zone[*pointer + sizeof(uint16_t)];
        const uint8_t *slot_payload = &aux_zone[*pointer + header_size];
        size_t payload_len = cur_size - header_size;

        bool is_match = false;
        bool matched_as_public = false;

        // Always try to match public (zero-key) entries first
        if (payload_len >= AUX_PROTECTION_ZERO_SIZE) {
            bool protection_ok = true;
            for (int i = 0; i < AUX_PROTECTION_ZERO_SIZE; i++) {
                if (slot_payload[payload_len - AUX_PROTECTION_ZERO_SIZE + i] != 0) {
                    protection_ok = false;
                    break;
                }
            }
            if (protection_ok) {
                is_match = true;
                matched_as_public = true;
            }
        }

        // If not a public entry and key is non-zero, try key-derived decryption
        if (!is_match && !key_zero) {
            is_match = decrypt_and_verify_aux_payload(slot_payload, payload_len, slot_iv, key);
        }

        if (!is_match) {
            *pointer += cur_size;
            continue;
        }

        // Key matched — return a copy of the slot with decrypted content (without protection zero)
        size_t content_bytes = payload_len - AUX_PROTECTION_ZERO_SIZE;
        size_t ret_size = sizeof(AuxSlot) + content_bytes;
        AuxSlot * ret_agg_union = malloc(ret_size > sizeof(AuxSlot) ? ret_size : sizeof(AuxSlot));

        // Copy size field (reflecting content without protection zero)
        uint16_t ret_size_le = htole16((uint16_t)ret_size);
        memcpy(&ret_agg_union->size, &ret_size_le, sizeof(ret_size_le));

        // Copy IV
        memcpy(ret_agg_union->iv, slot_iv, AES_BLOCKLEN);

        // Decrypt and copy content (without protection zero)
        if (matched_as_public) {
            // No encryption was applied, just copy the content portion
            memcpy(ret_agg_union->content_char32_be, slot_payload, content_bytes);
         } else {
            // Decrypt the full payload, then copy content without protection zero
            uint8_t *decrypted = malloc(payload_len);
            if (!decrypted) {
                free(ret_agg_union);
                return NULL;
            }
            uint8_t aes_key[HASHLEN];
            sha256_digest_all(key, HASHLEN, aes_key);
            memcpy(decrypted, slot_payload, payload_len);
            struct AES_ctx ctx;
            AES_init_ctx_iv(&ctx, aes_key, slot_iv);
            AES_CBC_decrypt_buffer(&ctx, decrypted, payload_len);
            memcpy(ret_agg_union->content_char32_be, decrypted, content_bytes);
            free(decrypted);
         }

        *pointer += cur_size;

        // Set output parameters
        if (out_is_public) *out_is_public = matched_as_public;
        if (out_offset) *out_offset = *pointer - cur_size; // offset of this slot

        return ret_agg_union;
    }
}


bool add_new_aux_to_aux_zone(uint8_t aux_zone[], size_t aux_zone_size, const uint8_t key[HASHLEN], char32_t content_char32_be[], size_t content_size) {
    if (aux_zone_size == 0) {
        return false;
    }

    // the last few bytes are terminators.
    aux_zone_size -= sizeof(aux_zone_terminator_magic);

    // Calculate the total size of the new AuxSlot
    // plaintext = content || protection_zero, padded to AES_BLOCKLEN for CBC
    size_t content_bytes = content_size * sizeof(char32_t);
    size_t plaintext_len = content_bytes + AUX_PROTECTION_ZERO_SIZE;
    size_t padded_len = round_up_aes_blocklen(plaintext_len);
    size_t slot_size = offsetof(AuxSlot, content_char32_be) + padded_len;

    if (slot_size > UINT16_MAX) {
        return false; // slot too large for uint16_t size field
    }

    // Walk through the aux zone to find the first free position (where size == 0)
    size_t pos = 0;
    while (pos < aux_zone_size) {
        uint16_t cur_size;
        memcpy(&cur_size, &aux_zone[pos], sizeof(cur_size));
        cur_size = le16toh(cur_size);
        if (cur_size == 0) {
            break; // found free space
        }
        if (cur_size > aux_zone_size - pos - sizeof(uint16_t)) {
            print_error(_("corrupted aux zone: slot size exceeds remaining space"));
        }
        pos += cur_size;
    }

    // Check if there is enough space for the new slot plus a trailing zero marker
    if (pos + slot_size + sizeof(uint16_t) > aux_zone_size) {
        return false; // not enough space
    }

    // Prepare the plaintext: content || protection_zero, zero-padded to AES block boundary
    uint8_t *plaintext = malloc(padded_len);
    if (!plaintext) return false;
    memset(plaintext, 0, padded_len);
    memcpy(plaintext, content_char32_be, content_bytes);
    // protection zero is already zero from memset

    // Generate a random per-slot IV
    uint8_t iv[AES_BLOCKLEN];
    fill_secure_random_bits(iv, AES_BLOCKLEN);

    // Encrypt if key is not zero
    if (!is_key_zero(key)) {
        uint8_t aes_key[HASHLEN];
        sha256_digest_all(key, HASHLEN, aes_key);
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, aes_key, iv);
        AES_CBC_encrypt_buffer(&ctx, plaintext, padded_len);
    }
    // else: key is zero, no encryption — store plaintext directly

    // Write the new AuxSlot
    uint16_t slot_size_le = htole16((uint16_t)slot_size);
    size_t header_size = offsetof(AuxSlot, content_char32_be);
    memcpy(&aux_zone[pos], &slot_size_le, sizeof(slot_size_le));
    memcpy(&aux_zone[pos + sizeof(slot_size_le)], iv, AES_BLOCKLEN);
    // Zero the padding between iv and content_char32_be (if any)
    if (header_size > sizeof(slot_size_le) + AES_BLOCKLEN) {
        memset(&aux_zone[pos + sizeof(slot_size_le) + AES_BLOCKLEN], 0, header_size - sizeof(slot_size_le) - AES_BLOCKLEN);
    }
    memcpy(&aux_zone[pos + header_size], plaintext, padded_len);
    free(plaintext);
    pos += slot_size;

    // Write the zero terminator for the next free slot
    memset(&aux_zone[pos], 0, sizeof(uint16_t));

    return true;
}
void remove_aux_from_aux_zone_by_key(uint8_t aux_zone[], size_t aux_zone_size, const uint8_t key[HASHLEN]) {
    if (aux_zone_size == 0) {
        return;
    }

    bool key_zero = is_key_zero(key);
    size_t read_pos = 0;
    size_t write_pos = 0;

    // the last few bytes are terminators.
    aux_zone_size -= sizeof(aux_zone_terminator_magic);

    while (read_pos < aux_zone_size) {
        uint16_t cur_size;
        memcpy(&cur_size, &aux_zone[read_pos], sizeof(cur_size));
        cur_size = le16toh(cur_size);
        if (cur_size == 0) {
            break; // end of aux zone
        }
        if (cur_size > aux_zone_size - read_pos - sizeof(uint16_t)) {
            print_error(_("Aux zone has corrupted. Use argument --no-aux"));
        }

        // Check if this slot matches the given key by attempting decryption and verifying protection zero
        size_t header_size = offsetof(AuxSlot, content_char32_be);
        bool is_match = false;

        if (cur_size >= header_size + AUX_PROTECTION_ZERO_SIZE) {
            const uint8_t *slot_iv = &aux_zone[read_pos + sizeof(uint16_t)];
            const uint8_t *slot_payload = &aux_zone[read_pos + header_size];
            size_t payload_len = cur_size - header_size;

            if (key_zero) {
                // For zero key: check if the entry is a public (unencrypted) entry
                // by verifying protection zero in plaintext
                if (payload_len >= AUX_PROTECTION_ZERO_SIZE) {
                    bool protection_ok = true;
                    for (int i = 0; i < AUX_PROTECTION_ZERO_SIZE; i++) {
                        if (slot_payload[payload_len - AUX_PROTECTION_ZERO_SIZE + i] != 0) {
                            protection_ok = false;
                            break;
                        }
                    }
                    is_match = protection_ok;
                }
            } else {
                // For non-zero key: try to decrypt and verify protection zero
                is_match = decrypt_and_verify_aux_payload(slot_payload, payload_len, slot_iv, key);
            }
        }

        if (is_match) {
            // Skip this slot (remove it)
            read_pos += cur_size;
        } else {
            // Keep this slot: memmove to write_pos if needed
            if (write_pos != read_pos) {
                memmove(&aux_zone[write_pos], &aux_zone[read_pos], cur_size);
            }
            write_pos += cur_size;
            read_pos += cur_size;
        }
    }

    // Zero out the remaining area after the last written slot
    if (write_pos < aux_zone_size) {
        memset(&aux_zone[write_pos], 0, aux_zone_size - write_pos);
    }
}


// Parse multibyte input string into a char32_t array for aux content.
// input: null-terminated multibyte string (e.g., UTF-8 from command line)
// out_content: pointer to char32_t* that will be set to a malloc'd array (caller must free)
// out_content_size: pointer to size_t that will be set to the number of char32_t elements
// On platforms with __STDC_UTF_32__, uses mbrtoc32 for full multibyte conversion.
// On platforms without __STDC_UTF_32__, only ASCII input is allowed.
void parse_mb_to_char32(const char * input, char32_t ** out_content, size_t * out_content_size) {
    size_t input_len = strlen(input);

    // Worst case: each byte becomes one char32_t, plus null terminator
    size_t content_cap = input_len + 1;
    char32_t * content = malloc(content_cap * sizeof(char32_t));
    if (content == NULL) {
        print_error(_("Failed to allocate memory for aux content"));
    }

    size_t content_size = 0;
#ifdef __STDC_UTF_32__
    // Platform supports UTF-32: use mbrtoc32 to convert multibyte to char32_t
    mbstate_t state = {0};
    const char * ptr = input;
    size_t remaining = input_len;
    while (remaining > 0) {
        char32_t c32;
        size_t ret = mbrtoc32(&c32, ptr, remaining, &state);
        if (ret == (size_t)-1 || ret == (size_t)-2) {
            // Invalid or incomplete multibyte sequence
            print_error(_("Invalid multibyte sequence in content"));
        } else if (ret == 0) {
            // Null character encoded
            ptr++;
            remaining--;
            content[content_size++] = 0;
        } else {
            content[content_size++] = c32;
            ptr += ret;
            remaining -= ret;
        }
    }
#else
    // No __STDC_UTF_32__: only allow ASCII input
    for (size_t i = 0; i < input_len; i++) {
        unsigned char ch = (unsigned char)input[i];
        if (ch > 0x7F) {
            print_error(_("Non-ASCII character in content, but this platform does not support UTF-32. "
                          "Only ASCII content is allowed."));
        }
        content[content_size++] = (char32_t)ch;
    }
#endif

    *out_content = content;
    *out_content_size = content_size;
}


void compose_shell_content(const char * cmd, uint8_t flags, uint16_t timeout, char32_t ** out_content,
     size_t * out_content_size){
    AuxContentShell aux_shell;
    aux_shell.aux_type = NMOBJ_AUX_TYPE_SHELL;
    aux_shell.flags = flags;
    aux_shell.timeout = htole16(timeout);

    parse_mb_to_char32(cmd, out_content, out_content_size);
    aux_shell.command_len = htole16((uint16_t)*out_content_size);

    size_t new_size_bytes = sizeof(AuxContentShell) + (*out_content_size) * sizeof(char32_t);
    char32_t *new_buf = realloc(*out_content, new_size_bytes);
    if (!new_buf){
        perror("realloc");
        exit(1);
    }
    *out_content = new_buf;

    memmove((uint8_t *)(*out_content) + sizeof(AuxContentShell), *out_content, (*out_content_size) * sizeof(char32_t));
    memcpy(*out_content, &aux_shell, sizeof(AuxContentShell));

    *out_content_size += sizeof(AuxContentShell) / sizeof(char32_t);
}

void compose_link_open_content(char32_t target_key[], uint16_t target_key_len,
     uint8_t flags, uint8_t uuid[16], int8_t unlock_level, uint8_t prio,
     char32_t ** out_content, size_t * out_content_size){
    AuxContentLinkOpen link_header;
    link_header.aux_type = NMOBJ_AUX_TYPE_LINK_OPEN;
    link_header.flags = flags;
    link_header.target_unlock_level = unlock_level;
    link_header.prio = prio;
    memcpy(link_header.target_uuid, uuid, 16);
    link_header.target_key_len = htole16(target_key_len);
    size_t total_bytes = sizeof(AuxContentLinkOpen) + target_key_len * sizeof(char32_t);
    char32_t *buf = malloc(total_bytes);
    if (!buf){
        perror("malloc");
        exit(1);
    }
    memcpy(buf, &link_header, sizeof(AuxContentLinkOpen));
    memcpy((uint8_t *)buf + sizeof(AuxContentLinkOpen), target_key, target_key_len * sizeof(char32_t));

    *out_content = buf;
    *out_content_size = (sizeof(AuxContentLinkOpen) + target_key_len * sizeof(char32_t)) / sizeof(char32_t);
}


// Print a single aux entry returned by probe_aux_from_aux_zone.
// Only handles PLAINTEXT — used during Open to display aux notes.
void print_aux_entry(const AuxSlot * slot, uint32_t offset, bool is_public, int index) {
    uint16_t slot_size_le;
    memcpy(&slot_size_le, &slot->size, sizeof(slot_size_le));
    uint16_t slot_size = le16toh(slot_size_le);
    size_t content_bytes = slot_size - sizeof(AuxSlot);
    size_t content_count = content_bytes / sizeof(char32_t);

    if (content_count == 0) {
        assert(false && "content_count == 0");
        return;
    }

    uint8_t aux_type = ((uint8_t *)slot->content_char32_be)[0];
    if (aux_type != NMOBJ_AUX_TYPE_PLAINTEXT) return;

    printf(_("Aux entry %d: %zu bytes, offset %u, %s\n"),
    index, content_bytes, offset,
    is_public ? _("public") : _("encrypted"));

    printf("  IV: ");
    print_hex_array(AES_BLOCKLEN, slot->iv);

    printf("  Content: ");
    for (size_t i = 0; i < content_count; i++) {
        char32_t c32 = slot->content_char32_be[i];
#ifdef __STDC_UTF_32__
        mbstate_t mbs = {0};
        char mb[MB_LEN_MAX];
        size_t r = c32rtomb(mb, c32, &mbs);
        if (r != (size_t)-1 && r > 0) {
            fwrite(mb, 1, r, stdout);
        } else {
            printf("U+%04X", (unsigned int)c32);
        }
#else
        printf("U+%04X", (unsigned int)c32);
#endif
    }
    printf("\n");
}


// Print LINK_OPEN details — used by --aux-probe only, not during Open.
void print_link_open_entry(const AuxSlot * slot, uint32_t offset, bool is_public, int index) {
    uint16_t slot_size_le;
    memcpy(&slot_size_le, &slot->size, sizeof(slot_size_le));
    uint16_t slot_size = le16toh(slot_size_le);
    size_t content_bytes = slot_size - sizeof(AuxSlot);

    AuxContentLinkOpen lh;
    memcpy(&lh, slot->content_char32_be, sizeof(lh));

    printf(_("Aux entry %d: %zu bytes, offset %u, %s\n"),
        index, content_bytes, offset,
        is_public ? _("public") : _("encrypted"));
    printf("  IV:           ");
    print_hex_array(AES_BLOCKLEN, slot->iv);
    printf(_("  Type:         LINK_OPEN\n"));
    printf(_("  Priority:     %u\n"), lh.prio);
    printf(_("  Flags:        %u"), lh.flags);
    if (lh.flags & AUX_CONTENT_LINK_OPEN_FLG_STOP_EXEC_NEXT_IF_SUCC) {
        printf(" (SHORTCUT)");
    }
    printf("\n");
    printf(_("  Unlock level: %u\n"), lh.target_unlock_level);
    printf(_("  Passwd chars: %u\n"), le16toh(lh.target_key_len));
    printf(_("  Target UUID:  %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n"),
        lh.target_uuid[0],lh.target_uuid[1],lh.target_uuid[2],lh.target_uuid[3],
        lh.target_uuid[4],lh.target_uuid[5],lh.target_uuid[6],lh.target_uuid[7],
        lh.target_uuid[8],lh.target_uuid[9],lh.target_uuid[10],lh.target_uuid[11],
        lh.target_uuid[12],lh.target_uuid[13],lh.target_uuid[14],lh.target_uuid[15]);
}


// Print SHELL command details
void print_shell_entry(const AuxSlot * slot, uint32_t offset, bool is_public, int index) {
    uint16_t slot_size_le;
    memcpy(&slot_size_le, &slot->size, sizeof(slot_size_le));
    uint16_t slot_size = le16toh(slot_size_le);
    size_t content_bytes = slot_size - sizeof(AuxSlot);

    AuxContentShell sh;
    memcpy(&sh, slot->content_char32_be, sizeof(sh));

    printf(_("Aux entry %d: %zu bytes, offset %u, %s\n"),
        index, content_bytes, offset,
        is_public ? _("public") : _("encrypted"));
    printf("  IV:           ");
    print_hex_array(AES_BLOCKLEN, slot->iv);
    printf(_("  Type:         SHELL\n"));
    printf(_("  Flags:        %u"), sh.flags);
    if (sh.flags & AUX_CONTENT_SHELL_FLG_EXEC_NEXT_IF_FAIL) {
        printf(" (SKIPPABLE)");
    }
    if (sh.flags & AUX_CONTENT_SHELL_FLG_STOP_EXEC_NEXT_IF_SUCC) {
        printf(" (SHORTCUT)");
    }

    printf("\n");
    printf(_("  Timeout:      %u sec\n"), le16toh(sh.timeout));
    uint16_t cmd_len = le16toh(sh.command_len);
    printf(_("  Command:      "));
    if (cmd_len > 0) {
        const char32_t *cmd_chars = slot->content_char32_be + sizeof(AuxContentShell) / sizeof(char32_t);
        for (uint16_t i = 0; i < cmd_len; i++) {
            char32_t c32 = cmd_chars[i];
#ifdef __STDC_UTF_32__
            mbstate_t mbs = {0};
            char mb[MB_LEN_MAX];
            size_t r = c32rtomb(mb, c32, &mbs);
            if (r != (size_t)-1 && r > 0) {
                fwrite(mb, 1, r, stdout);
            } else {
                printf("U+%04X", (unsigned int)c32);
            }
#else
            printf("U+%04X", (unsigned int)c32);
#endif
        }
    } else {
        printf(_("(empty)"));
    }
    printf("\n");
}


// Convert char32_t array to a null-terminated multibyte string.
// input: char32_t array; input_size: number of char32_t elements.
// Returns malloc'd multibyte string on success; NULL if any character
// cannot be converted (caller treats this as execution failure).
static char *parse_char32_to_mb(const char32_t *input, size_t input_size) {
    size_t max_mb = input_size * MB_CUR_MAX + 1;
    char *mb = malloc(max_mb);
    if (!mb) return NULL;

    size_t mb_pos = 0;
#ifdef __STDC_UTF_32__
    mbstate_t state = {0};
    for (size_t i = 0; i < input_size; i++) {
        char buf[MB_LEN_MAX];
        size_t ret = c32rtomb(buf, input[i], &state);
        if (ret == (size_t)-1) {
            free(mb);
            return NULL;
        }
        for (size_t j = 0; j < ret; j++) {
            mb[mb_pos++] = buf[j];
        }
    }
#else
    // No __STDC_UTF_32__: only allow ASCII range
    for (size_t i = 0; i < input_size; i++) {
        if (input[i] > 0x7F) {
            free(mb);
            return NULL;
        }
        mb[mb_pos++] = (char)input[i];
    }
#endif
    mb[mb_pos] = '\0';
    return mb;
}


// Thread argument for shell command execution
typedef struct { const char *cmd; int result; } ShellThreadArg;

static int shell_thread_fn(void *a) {
    ShellThreadArg *ta = (ShellThreadArg *)a;
    ta->result = system(ta->cmd);
    return 0;
}
// opened_names[]: list of /dev/mapper names currently opened by this cascade;
//   "@" in the command is replaced with these names joined by commas.
// Returns true if the command executed successfully, false otherwise.
bool exec_aux_cmd_from_probed_aux(const AuxSlot *slot, char * opened_names[], size_t opened_names_len) {
    assert(slot && "slot is NULL");

    uint16_t slot_size_le;
    memcpy(&slot_size_le, &slot->size, sizeof(slot_size_le));
    size_t content_bytes = le16toh(slot_size_le) - sizeof(AuxSlot);

    if (content_bytes < sizeof(AuxContentShell)) return false;

    AuxContentShell shell_header;
    memcpy(&shell_header, slot->content_char32_be, sizeof(AuxContentShell));
    if (shell_header.aux_type != NMOBJ_AUX_TYPE_SHELL) return false;

    uint16_t command_len = le16toh(shell_header.command_len);
    assert(command_len > 0 && "command is empty.");

    const char32_t *command_data = slot->content_char32_be + sizeof(AuxContentShell) / sizeof(char32_t);
    char *mb_cmd = parse_char32_to_mb(command_data, command_len);
    if (!mb_cmd) {
        print_warning(_("Failed to convert command to multibyte. Your system is using "
            "an encoding that is a subset of Unicode. The provided command contains Non-ASCII "
            "characters."));
        return false;
    }

    // Replace "@" with comma-separated opened_names
    if (opened_names != NULL && opened_names_len > 0) {
        // Build replacement string
        size_t names_total_len = 0;
        for (size_t i = 0; i < opened_names_len; i++) {
            names_total_len += strlen(opened_names[i]) + 1; // +1 for comma
        }
        char *names_str = malloc(names_total_len + 1);
        if (names_str) {
            names_str[0] = '\0';
            for (size_t i = 0; i < opened_names_len; i++) {
                if (i > 0) strcat(names_str, ",");
                strcat(names_str, opened_names[i]);
            }
            // Replace all "@" in mb_cmd with names_str
            char *at_pos;
            size_t names_len = strlen(names_str);
            while ((at_pos = strchr(mb_cmd, '@')) != NULL) {
                size_t prefix_len = (size_t)(at_pos - mb_cmd);
                size_t suffix_len = strlen(at_pos + 1);
                size_t new_len = prefix_len + names_len + suffix_len + 1;
                char *new_cmd = malloc(new_len);
                if (!new_cmd) { free(names_str); free(mb_cmd); return false; }
                memcpy(new_cmd, mb_cmd, prefix_len);
                memcpy(new_cmd + prefix_len, names_str, names_len);
                memcpy(new_cmd + prefix_len + names_len, at_pos + 1, suffix_len + 1);
                free(mb_cmd);
                mb_cmd = new_cmd;
            }
            free(names_str);
        }
    }

    printf(_("exec: %s\n"), mb_cmd);

    uint16_t timeout_secs = le16toh(shell_header.timeout);
    int ret;

    if (timeout_secs > 0) {
#ifdef __STDC_NO_THREADS__
        print_warning(_("Shell command timeout (%u sec) requested but ISO C threads unavailable. "
                        "Command will run without timeout."), timeout_secs);
        ret = system(mb_cmd);
#else
        // Run system() in a separate thread, join with timeout
        ShellThreadArg arg = { mb_cmd, -1 };

        thrd_t thr;
        if (thrd_create(&thr, shell_thread_fn, &arg) != thrd_success) {
            print_warning(_("Failed to create thread for shell command execution."));
            ret = system(mb_cmd);
        } else {
            // Poll with thrd_sleep for timeout
            struct timespec start, now;
            timespec_get(&start, TIME_UTC);
            int join_result;
            while (true) {
                timespec_get(&now, TIME_UTC);
                if ((now.tv_sec - start.tv_sec) >= timeout_secs) {
                    // Timeout: stop waiting, return failure (thread may still run)
                    print_warning(_("Shell command timed out after %u seconds."), timeout_secs);
                    ret = -1;
                    break;
                }
                join_result = thrd_join(thr, NULL);
                if (join_result != thrd_busy) {
                    ret = arg.result;
                    break;
                }
                thrd_sleep(&(struct timespec){.tv_sec = 0, .tv_nsec = 100000000}, NULL);
            }
        }
#endif
    } else {
        ret = system(mb_cmd);
    }

    free(mb_cmd);
    return ret == 0;
}

bool get_aux_link_open_data(const AuxSlot *slot, uint8_t uuid[],
     int8_t *out_unlock_level, uint8_t *out_prio, uint8_t *out_flags,
     char32_t ** target_key, uint16_t * target_key_len){
    assert(slot && "slot is NULL");

    uint16_t slot_size_le;
    memcpy(&slot_size_le, &slot->size, sizeof(slot_size_le));
    size_t content_bytes = le16toh(slot_size_le) - sizeof(AuxSlot);

    if (content_bytes < sizeof(AuxContentLinkOpen)){
        return false;
    } 

    AuxContentLinkOpen header;
    memcpy(&header, slot->content_char32_be, sizeof(AuxContentLinkOpen));
    if (header.aux_type != NMOBJ_AUX_TYPE_LINK_OPEN){
        return false;
    }

    memcpy(uuid, header.target_uuid, 16);
    if (out_unlock_level) *out_unlock_level = header.target_unlock_level;
    if (out_prio) *out_prio = header.prio;
    if (out_flags) *out_flags = header.flags;

    uint16_t key_len = le16toh(header.target_key_len);
    assert(key_len && "key_len is 0"); 

    assert(sizeof(AuxContentLinkOpen) + key_len * sizeof(char32_t) <= content_bytes && "illgal content"); 

    *target_key = malloc(key_len * sizeof(char32_t));
    if (!*target_key){
        perror("malloc");
        exit(1);
    }

    const char32_t *key_data = slot->content_char32_be + sizeof(AuxContentLinkOpen) / sizeof(char32_t);
    memcpy(*target_key, key_data, key_len * sizeof(char32_t));
    *target_key_len = key_len;
    return true;
}


#endif
