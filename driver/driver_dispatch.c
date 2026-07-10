// driver_dispatch.c — driver vtable, selection, and dispatch
#pragma once

#ifndef INCL_DRIVER_DISPATCH
#define INCL_DRIVER_DISPATCH

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "../include/windham_const.h"

// ── Driver vtable ──────────────────────────────────

typedef struct Driver {
    const char *name;       // "dm-mapper", "decrypt", "shell", "print"

    void (*init)(const char *driver_name);

    int  (*try_create)(const char *file_name, const char *enc_type,
                       const char *tmp_name);

    int  (*create)(const char *device, const char *name, const char *enc_type,
                   const char *password, char uuid_str[37],
                   size_t start_sector, size_t end_sector, size_t block_size,
                   bool is_read_only, bool is_allow_discards,
                   bool is_no_read_workqueue, bool is_no_write_workqueue);

    void (*remove)(const char *name, bool is_deferred_remove);

    void (*remove_by_uuid)(const char uuid_str[37]);

    bool (*linear_map)(const char *device, const char *name,
                       uint64_t start, uint64_t size, const char uuid_str[37]);

    void (*map_partition_table)(const char *name, bool is_new_map);
} Driver;

// ── Dispatch API ───────────────────────────────────

void driver_init_all(const char *act_driver_name);
int  try_create_crypt_mapping(const char *file_name, const char *enc_type,
                              const char *tmp_name);
int  create_crypt_mapping(const char *device, const char *name,
                          const char *enc_type, const char *password,
                          char uuid_str[37],
                          size_t start_sector, size_t end_sector,
                          size_t block_size,
                          bool is_read_only, bool is_allow_discards,
                          bool is_no_read_workqueue, bool is_no_write_workqueue);
void remove_crypt_mapping(const char *name, bool is_deferred_remove);
void remove_crypt_mapping_by_uuid(const char uuid_str[37]);
bool linear_map(const char *device, const char *name,
                uint64_t start, uint64_t size, const char uuid_str[37]);
void map_partition_table(const char *name, bool is_new_map);

void convert_disk_key_to_hex_format(const uint8_t *key, size_t key_size,
                                    char *out_hex);

void create_crypt_mapping_from_disk_key(
    const char *device, const char *target_name, const char *enc_type,
    const uint8_t *disk_key, size_t disk_key_size, uint8_t uuid[16],
    size_t start_sector, size_t end_sector, size_t block_size,
    bool read_only, bool is_allow_discards,
    bool is_no_read_workqueue, bool is_no_write_workqueue,
    bool is_no_map_partition);

enum {
    EMOBJ_try_create_crypt_mapping_OK,
    EMOBJ_try_create_crypt_mapping_FAILED_INIT,
    EMOBJ_try_create_crypt_mapping_FAILED_MAPPING,
};

void decrypt_set_output_file(const char *path);

// ── Driver registry (ordered by priority) ───────────

#ifndef WINDHAM_ISOC
extern Driver driver_dm_mapper;
#endif
extern Driver driver_decrypt;
extern Driver driver_shell;
extern Driver driver_print;

static Driver *drivers[] = {
#ifndef WINDHAM_ISOC
    &driver_dm_mapper,
#endif
    &driver_decrypt,
    &driver_shell,
    &driver_print,
    NULL
};

Driver *current_driver = NULL;
bool    is_device_mapper_available = false;

// ── init ────────────────────────────────────────────

void driver_init_all(const char *act_driver_name) {
    if (act_driver_name && act_driver_name[0]) {
        // force a specific driver
        for (int i = 0; drivers[i]; i++) {
            if (strcmp(drivers[i]->name, act_driver_name) == 0) {
                drivers[i]->init(act_driver_name);
                if (is_device_mapper_available) {
                    current_driver = drivers[i];
                    return;
                }
                print_error(_("driver '%s' initialisation failed."), act_driver_name);
            }
        }
        print_error(_("unknown driver '%s'."), act_driver_name);
    }

    // auto-select by priority
    for (int i = 0; drivers[i]; i++) {
        drivers[i]->init(NULL);
        if (is_device_mapper_available) {
            current_driver = drivers[i];
            return;
        }
    }
    print_error(_("no driver could be initialised."));
}

// ── dispatch wrappers ───────────────────────────────

int try_create_crypt_mapping(const char *f, const char *e, const char *t) {
    return current_driver->try_create(f, e, t);
}

int create_crypt_mapping(
    const char *dev, const char *name, const char *enc, const char *pwd,
    char uuid[37], size_t ss, size_t es, size_t bs,
    bool ro, bool ad, bool nrq, bool nwq)
{
    return current_driver->create(dev, name, enc, pwd, uuid, ss, es, bs, ro, ad, nrq, nwq);
}

void remove_crypt_mapping(const char *n, bool d) { current_driver->remove(n, d); }
void remove_crypt_mapping_by_uuid(const char u[37]) { current_driver->remove_by_uuid(u); }

bool linear_map(const char *d, const char *n, uint64_t s, uint64_t sz, const char u[37]) {
    return current_driver->linear_map(d, n, s, sz, u);
}

void map_partition_table(const char *n, bool b) { current_driver->map_partition_table(n, b); }

// ── convert_disk_key_to_hex_format ──────────────────

void convert_disk_key_to_hex_format(const uint8_t *key, size_t key_size, char *out) {
    const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < key_size; i++) {
        out[i * 2]     = hex[(key[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[key[i] & 0xF];
    }
    out[key_size * 2] = '\0';
}

// ── create_crypt_mapping_from_disk_key (library fn) ──

void create_crypt_mapping_from_disk_key(
    const char *device, const char *target_name, const char *enc_type,
    const uint8_t *disk_key, size_t disk_key_size, uint8_t uuid[16],
    size_t start_sector, size_t end_sector, size_t block_size,
    bool read_only, bool is_allow_discards,
    bool is_no_read_workqueue, bool is_no_write_workqueue,
    bool is_no_map_partition)
{
    char *password = malloc(disk_key_size * 2 + 1);
    if (!password) { perror("malloc"); exit(1); }
    convert_disk_key_to_hex_format(disk_key, disk_key_size, password);

    char uuid_str[37];
    generate_UUID_from_bytes(uuid, uuid_str);

    create_crypt_mapping(device, target_name, enc_type, password, uuid_str,
                         start_sector, end_sector, block_size,
                         read_only, is_allow_discards,
                         is_no_read_workqueue, is_no_write_workqueue);
    free(password);

    if (!is_no_map_partition)
        map_partition_table(target_name, true);
}

// ── Driver implementations ──────────────────────────

#ifndef WINDHAM_ISOC
#include "driver_dm_mapper.c"
#endif
#include "driver_decrypt.c"
#include "driver_shell.c"
#include "driver_print.c"

#endif
