// driver_dm_mapper.c -- dm-crypt ioctl driver

#define _GNU_SOURCE

#if !defined(WINDHAM_PLAT_GNU_LINUX) && !defined(CFG_DRIVER_NO_DMMAPPER)
#error "dm-mapper driver is avaliable only for GNU/Linux target"
#endif


#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/windham_const.h"
#include "../libsrc/srclib.c"
#include "../libplat/GNU_Linux/dm_ioctl.c"

// -- init --------------------------------------------

static void dm_mapper_init(const char *driver_name) {
    (void)driver_name;
    mapper_init();  // from dm_ioctl.c -- opens /dev/mapper/control
}

// -- try_create --------------------------------------

static int dm_mapper_try_create(const char *file, const char *enc, const char *tmp) {
    if (!is_device_mapper_available)
        return EMOBJ_try_create_crypt_mapping_FAILED_INIT;

    char name[] = "windham-tmp-XXXXXX";
    memcpy(name + strlen("windham-tmp-"), tmp, 6);

    if (!dm_dev_create(name, NULL))
        return EMOBJ_try_create_crypt_mapping_FAILED_INIT;

    char params[540];
    snprintf(params, sizeof(params),
        "%s e8cfa3dbfe373b536be43c5637387786c01be00ba5f730aacb039e86f3eb72f3 0 %s 0",
        enc, file);

    struct { struct dm_target_spec spec; char params[540]; } tbl;
    memset(&tbl, 0, sizeof(tbl));
    tbl.spec.sector_start = 0;
    tbl.spec.length       = 8;
    strncpy(tbl.spec.target_type, "crypt", 16);
    memcpy(tbl.params, params, strlen(params) + 1);

    if (!dm_table_load(name, 1, &tbl,
        sizeof(struct dm_target_spec) + strlen(params) + 1)) {
        dm_dev_remove(name, false);
        return EMOBJ_try_create_crypt_mapping_FAILED_INIT;
    }
    if (!dm_dev_resume(name)) {
        dm_dev_remove(name, false);
        return EMOBJ_try_create_crypt_mapping_FAILED_MAPPING;
    }
    if (!dm_dev_remove(name, false))
        return EMOBJ_try_create_crypt_mapping_FAILED_INIT;

    return EMOBJ_try_create_crypt_mapping_OK;
}

// -- create ------------------------------------------

static int dm_mapper_create(
    const char *device, const char *name, const char *enc_type,
    const char *password, char uuid_str[37],
    size_t start_sector, size_t end_sector, size_t block_size,
    bool is_read_only, bool is_allow_discards,
    bool is_no_read_workqueue, bool is_no_write_workqueue)
{
    if (!is_device_mapper_available) {
        print_error(_("device-mapper not available.\nDevice: %s\nUUID: %s"),
                    device, uuid_str);
    }
    if (!dm_create_crypt(name, uuid_str, enc_type, password, device,
                         start_sector, end_sector - start_sector,
                         (uint32_t)block_size,
                         is_read_only, is_allow_discards,
                         is_no_read_workqueue, is_no_write_workqueue)) {
        print_error(_("dm ioctl failed when mapping crypt device %s."), name);
    }
    return 0;
}

// -- remove ------------------------------------------

static void dm_mapper_remove(const char *name, bool deferred) {
    if (!is_device_mapper_available) {
        print_error(_("cannot close /dev/mapper/%s: device-mapper missing."), name);
    }
    if (!dm_remove(name, deferred)) {
        print_error(_("failed to remove device %s."), name);
    }
}

// -- remove_by_uuid ----------------------------------

static void dm_mapper_remove_by_uuid(const char uuid_str[37]) {
    if (!is_device_mapper_available) return;
    dm_remove_by_uuid(uuid_str);
}

// -- linear_map --------------------------------------

static bool dm_mapper_linear_map(const char *dev, const char *name,
                                 uint64_t start, uint64_t size,
                                 const char uuid_str[37]) {
    if (!is_device_mapper_available) {
        print_warning(_("cannot map %s: dm not available."), name);
        return false;
    }
    if (!dm_create_linear(name, uuid_str, dev, start, size)) {
        print_warning(_("cannot map partition %s on %s."), name, dev);
        return false;
    }
    return true;
}

// -- map_partition_table -----------------------------

static void dm_mapper_map_partitions(const char *name, bool is_new) {
    // requires blkid -- keep this as a no-op for now
    // (was in libplat/GNU_Linux/mapper.c but depends on blkid dynamic loading)
    (void)name; (void)is_new;
}

Driver driver_dm_mapper = {
    .name               = "dm-mapper",
    .init               = dm_mapper_init,
    .try_create         = dm_mapper_try_create,
    .create             = dm_mapper_create,
    .remove             = dm_mapper_remove,
    .remove_by_uuid     = dm_mapper_remove_by_uuid,
    .linear_map         = dm_mapper_linear_map,
    .map_partition_table = dm_mapper_map_partitions,
};
