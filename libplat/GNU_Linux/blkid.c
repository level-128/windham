#include <stdbool.h>
#include <dlfcn.h>
#include <blkid/blkid.h>

#include "../../include/windham_const.h"

bool is_blkid_available = false;

blkid_probe (*p_blkid_new_probe)(void);
blkid_probe (*p_blkid_new_probe_from_filename)(const char *);
int (*p_blkid_probe_set_device)(blkid_probe, int, blkid_loff_t, blkid_loff_t);
int (*p_blkid_do_probe)(blkid_probe);
int (*p_blkid_probe_lookup_value)(blkid_probe, const char *, const char **, size_t *);
blkid_partlist (*p_blkid_probe_get_partitions)(blkid_probe);
int (*p_blkid_partlist_numof_partitions)(blkid_partlist);
blkid_partition (*p_blkid_partlist_get_partition)(blkid_partlist, int);
int (*p_blkid_partition_get_partno)(blkid_partition);
blkid_loff_t (*p_blkid_partition_get_start)(blkid_partition);
blkid_loff_t (*p_blkid_partition_get_size)(blkid_partition);
const char *(*p_blkid_partition_get_uuid)(blkid_partition);
int (*p_blkid_free_probe)(blkid_probe);

static void *blkid_handle = NULL;

void blkid_init(void) {
	void *handle = dlopen("libblkid.so", RTLD_LAZY);
	if (!handle) {
		print_warning(
			_("Cannot load libblkid.so. Some features or safety checks "
			  "that depend on blkid will be unavailable."));
		is_blkid_available = false;
		return;
	}
	blkid_handle = handle;

	p_blkid_new_probe               = dlsym(handle, "blkid_new_probe");
	p_blkid_new_probe_from_filename = dlsym(handle, "blkid_new_probe_from_filename");
	p_blkid_probe_set_device        = dlsym(handle, "blkid_probe_set_device");
	p_blkid_do_probe                = dlsym(handle, "blkid_do_probe");
	p_blkid_probe_lookup_value      = dlsym(handle, "blkid_probe_lookup_value");
	p_blkid_probe_get_partitions    = dlsym(handle, "blkid_probe_get_partitions");
	p_blkid_partlist_numof_partitions = dlsym(handle, "blkid_partlist_numof_partitions");
	p_blkid_partlist_get_partition  = dlsym(handle, "blkid_partlist_get_partition");
	p_blkid_partition_get_partno    = dlsym(handle, "blkid_partition_get_partno");
	p_blkid_partition_get_start     = dlsym(handle, "blkid_partition_get_start");
	p_blkid_partition_get_size      = dlsym(handle, "blkid_partition_get_size");
	p_blkid_partition_get_uuid      = dlsym(handle, "blkid_partition_get_uuid");
	p_blkid_free_probe              = dlsym(handle, "blkid_free_probe");

	is_blkid_available = true;
}
