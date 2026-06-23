/*
 * mapper.c — device-mapper operations via direct ioctl
 * No libdevmapper.so dependency.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dm_ioctl.c"
#include "../../include/windham_const.h"

/* mapper_init() is provided by dm_ioctl.c */

/* ── linear map (partition table entries) ──────────────────── */
bool linear_map(const char *device, const char *name,
		const uint64_t start, const uint64_t size,
		const char uuid_str[37])
{
	if (!is_device_mapper_available) {
		print_warning(_("cannot map partition %s: device-mapper not available."), name);
		return false;
	}
	if (!dm_create_linear(name, uuid_str, device, start, size)) {
		print_warning(_("cannot map partition %s according to the detected partition table on device %s."),
			      name, device);
		return false;
	}
	return true;
}

/* ── remove crypt mapping by UUID ──────────────────────────── */
void remove_crypt_mapping_by_uuid(const char uuid_str[37])
{
	if (!is_device_mapper_available) return;
	if (!dm_remove_by_uuid(uuid_str)) {
		print_warning(_("Failed when removing partition with UUID %s. Did you modify the partition table?"), uuid_str);
	}
}

/* ── map partition table (requires blkid) ──────────────────── */
void map_partition_table(const char *name, bool is_new_map)
{
	if (!is_blkid_available) {
		print_warning(_("Partition table mapping skipped: libblkid.so not loaded."));
		return;
	}
	char device[strlen("/dev/mapper/") + strlen(name) + 1];
	sprintf(device, "/dev/mapper/%s", name);

	blkid_probe pr = p_blkid_new_probe_from_filename(device);
	if (!pr) {
		perror("Failed to open device");
		p_blkid_free_probe(pr);
		return;
	}

	p_blkid_do_probe(pr);
	const blkid_partlist ls = p_blkid_probe_get_partitions(pr);
	if (ls != NULL) {
		int nparts = p_blkid_partlist_numof_partitions(ls);
		printf("Number of partitions: %d\n", nparts);
		for (int i = 0; i < nparts; i++) {
			blkid_partition par   = p_blkid_partlist_get_partition(ls, i);
			int             parid = p_blkid_partition_get_partno(par);
			char part_name[strlen(name) + strlen("-part" STRINGIFY(INTMAX_MAX)) + 1];
			printf("Partition %d: %d\n", i, parid);

			if (is_new_map) {
				blkid_loff_t start = p_blkid_partition_get_start(par);
				blkid_loff_t size  = p_blkid_partition_get_size(par);
				const char  *uuid  = p_blkid_partition_get_uuid(par);
				sprintf(part_name, "%s-part%i", name, parid);
				linear_map(device, part_name, start, size, uuid);
			} else {
				const char *uuid = p_blkid_partition_get_uuid(par);
				remove_crypt_mapping_by_uuid(uuid);
			}
		}
	}
	p_blkid_free_probe(pr);
}

/* ── remove crypt mapping by name ──────────────────────────── */
void remove_crypt_mapping(const char *name, bool is_deferred_remove)
{
	if (!is_device_mapper_available) {
		print_error(_("Failed to close device mapping at \"/dev/mapper/%s\" due to missing device mapper."), name);
	}
	map_partition_table(name, false);
	if (!dm_remove(name, is_deferred_remove)) {
		print_error(_("failed to remove device %s. Is device a device-mapper target?"), name);
	}
}

/* ── create a crypt mapping (from hex password string) ─────── */
int create_crypt_mapping(
	const char *device, const char *name, const char *enc_type,
	const char *password, char uuid_str[37],
	size_t start_sector, size_t end_sector, size_t block_size,
	bool is_read_only, bool is_allow_discards,
	bool is_no_read_workqueue, bool is_no_write_workqueue)
{
	if (!is_device_mapper_available) {
		print_error(_("Failed to create device mapping: device-mapper not available.\nDevice: %s\nUUID: %s"),
			    device, uuid_str);
	}

	if (!dm_create_crypt(name, uuid_str,
			     enc_type, password, device,
			     start_sector,
			     end_sector - start_sector,
			     (uint32_t)block_size,
			     is_read_only, is_allow_discards,
			     is_no_read_workqueue, is_no_write_workqueue)) {
		print_error(_("dm ioctl failed when mapping crypt device %s."), name);
	}
	return 0;
}

/* ── create crypt mapping from raw disk key ────────────────── */
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

	create_crypt_mapping(device, target_name, enc_type,
			     password, uuid_str,
			     start_sector, end_sector, block_size,
			     read_only, is_allow_discards,
			     is_no_read_workqueue, is_no_write_workqueue);
	free(password);

	if (!is_no_map_partition) {
		map_partition_table(target_name, true);
	}
}

/* ── try-create (ephemeral test mapping) ───────────────────── */
int try_create_crypt_mapping(const char *file_name, const char *enc_type,
			     const char *tmp_name)
{
	if (!is_device_mapper_available)
		return EMOBJ_try_create_crypt_mapping_FAILED_INIT;

	char name[] = "windham-tmp-XXXXXX";
	memcpy(name + strlen("windham-tmp-"), tmp_name, 6);

	/* Minimal test: create + load + resume + remove */
	if (!dm_dev_create(name, NULL))
		return EMOBJ_try_create_crypt_mapping_FAILED_INIT;

	char params[540];
	snprintf(params, sizeof(params),
		"%s e8cfa3dbfe373b536be43c5637387786c01be00ba5f730aacb039e86f3eb72f3 0 %s 0",
		enc_type, file_name);

	struct {
		struct dm_target_spec spec;
		char params[540];
	} tbl;
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
