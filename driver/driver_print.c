// driver_print.c — print driver (no-op, just displays what would happen)

#include <stdio.h>

static void print_init(const char *driver_name) {
    (void)driver_name;
    is_device_mapper_available = true;  // print is always available
}

static int print_try_create(const char *file, const char *enc, const char *tmp) {
    (void)file; (void)enc; (void)tmp;
    return EMOBJ_try_create_crypt_mapping_OK;
}

static int print_create(
    const char *device, const char *name, const char *enc_type,
    const char *password, char uuid_str[37],
    size_t start_sector, size_t end_sector, size_t block_size,
    bool is_read_only, bool is_allow_discards,
    bool is_no_read_workqueue, bool is_no_write_workqueue)
{
    (void)device; (void)enc_type; (void)password; (void)uuid_str;
    (void)start_sector; (void)end_sector; (void)block_size;
    (void)is_read_only; (void)is_allow_discards;
    (void)is_no_read_workqueue; (void)is_no_write_workqueue;
    printf("would create mapping: %s\n", name);
    return 0;
}

static void print_remove(const char *name, bool deferred) {
    (void)deferred;
    printf("would remove mapping: %s\n", name);
}

static void print_remove_by_uuid(const char uuid_str[37]) {
    printf("would remove mapping by UUID: %s\n", uuid_str);
}

static bool print_linear_map(const char *device, const char *name,
                             uint64_t start, uint64_t size,
                             const char uuid_str[37])
{
    (void)device; (void)name; (void)start; (void)size; (void)uuid_str;
    printf("would create linear map: %s\n", name);
    return true;
}

static void print_map_partitions(const char *name, bool is_new) {
    (void)is_new;
    printf("would map partitions: %s\n", name);
}

Driver driver_print = {
    .name               = "print",
    .init               = print_init,
    .try_create         = print_try_create,
    .create             = print_create,
    .remove             = print_remove,
    .remove_by_uuid     = print_remove_by_uuid,
    .linear_map         = print_linear_map,
    .map_partition_table = print_map_partitions,
};
