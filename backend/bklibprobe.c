#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "../include/windham_const.h"
#include "../libsrc/probelib.c"

#ifdef WINDHAM_HAS_MNTENT
#include <mntent.h>
#endif


/* -- read a line from /sys/dev/block/<major>:<minor>/<file>, trim newline -- */

static bool read_sysfs_block_line(unsigned major_num, unsigned minor_num,
                                  const char *fname, char *out, size_t out_size) {
	char path[256];
	snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/%s", major_num, minor_num, fname);
	FILE *fp = fopen(path, "r");
	if (!fp) return false;
	bool ok = (fgets(out, (int)out_size, fp) != NULL);
	fclose(fp);
	if (ok) {
		size_t end = strlen(out);
		while (end > 0 && (out[end-1] == '\n' || out[end-1] == '\r'))
			out[--end] = 0;
	}
	return ok;
}

static uint64_t read_sysfs_ulong(unsigned major_num, unsigned minor_num,
                                 const char *fname) {
	char buf[64] = {0};
	if (!read_sysfs_block_line(major_num, minor_num, fname, buf, sizeof(buf)))
		return UINT64_MAX;
	return strtoull(buf, NULL, 10);
}


/* -- print device info from /sys/dev/block/<major>:<minor>/ -- */

static void print_device_sysfs_info(const char *device_path,
                                    unsigned major_num, unsigned minor_num) {
	printf(_("Device: %s (%u:%u)\n"), device_path, major_num, minor_num);

	if (major_num > 0) {
		char val[256];

		if (read_sysfs_block_line(major_num, minor_num, "device/model", val, sizeof(val)))
			printf(_("  Model:      %s\n"), val);
		if (read_sysfs_block_line(major_num, minor_num, "device/vendor", val, sizeof(val)))
			printf(_("  Vendor:     %s\n"), val);
		if (read_sysfs_block_line(major_num, minor_num, "device/rev", val, sizeof(val)))
			printf(_("  Revision:   %s\n"), val);

		uint64_t size = read_sysfs_ulong(major_num, minor_num, "size");
		if (size != UINT64_MAX) {
			uint64_t bytes = size * 512;
			if (bytes >= (UINT64_C(1) << 40))
				printf(_("  Size:       %.2f TiB (%llu sectors)\n"),
				       (double)bytes / (UINT64_C(1) << 40), (unsigned long long)size);
			else if (bytes >= (UINT64_C(1) << 30))
				printf(_("  Size:       %.2f GiB (%llu sectors)\n"),
				       (double)bytes / (UINT64_C(1) << 30), (unsigned long long)size);
			else if (bytes >= (UINT64_C(1) << 20))
				printf(_("  Size:       %.2f MiB (%llu sectors)\n"),
				       (double)bytes / (UINT64_C(1) << 20), (unsigned long long)size);
			else
				printf(_("  Size:       %llu sectors\n"), (unsigned long long)size);
		}

		uint64_t removable = read_sysfs_ulong(major_num, minor_num, "removable");
		if (removable != UINT64_MAX)
			printf(_("  Removable:  %s\n"), removable ? _("yes") : _("no"));

		uint64_t ro = read_sysfs_ulong(major_num, minor_num, "ro");
		if (ro != UINT64_MAX)
			printf(_("  Read-only:  %s\n"), ro ? _("yes") : _("no"));

		uint64_t hw_sec = read_sysfs_ulong(major_num, minor_num, "queue/hw_sector_size");
		if (hw_sec != UINT64_MAX)
			printf(_("  HW sector:  %llu\n"), (unsigned long long)hw_sec);

		uint64_t log_sec = read_sysfs_ulong(major_num, minor_num, "queue/logical_block_size");
		if (log_sec != UINT64_MAX)
			printf(_("  Log. block: %llu\n"), (unsigned long long)log_sec);

		if (read_sysfs_block_line(major_num, minor_num, "wwid", val, sizeof(val)))
			printf(_("  WWID:       %s\n"), val);

#ifdef WINDHAM_HAS_MNTENT
		{
			FILE *mtab = setmntent("/proc/mounts", "r");
			if (mtab) {
				struct mntent *ent;
				while ((ent = getmntent(mtab)) != NULL) {
					if (strcmp(ent->mnt_fsname, device_path) == 0) {
						printf(_("  Mounted:    %s (%s)\n"), ent->mnt_dir, ent->mnt_type);
						break;
					}
				}
				endmntent(mtab);
			}
		}
#endif
	}
}


/* -- print formatted probe result -- */

void print_probe_device_result(const char *device_path,
                               unsigned major_num, unsigned minor_num,
                               const uint8_t uuid[16], int probe_type) {
	print_device_sysfs_info(device_path, major_num, minor_num);

	switch (probe_type) {
	case PROBE_RESULT_SHEBANG:
		printf(_("  Signature:  shebang (self-decrypt executable)\n"));
		break;
	case PROBE_RESULT_MAGIC:
		printf(_("  Signature:  windham partition magic\n"));
		break;
	case PROBE_RESULT_SUSPEND:
		printf(_("  Signature:  suspended header\n"));
		break;
	case PROBE_RESULT_ENTROPY:
		printf(_("  Status:     possible encrypted partition (no plaintext Windham signature)\n"));
		break;
	default:
		return;
	}

	printf(_("  UUID:       %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x\n"),
	       uuid[0], uuid[1], uuid[2], uuid[3],
	       uuid[4], uuid[5], uuid[6], uuid[7],
	       uuid[8], uuid[9], uuid[10], uuid[11],
	       uuid[12], uuid[13], uuid[14], uuid[15]);
	printf("\n");
}


/* -- probe a single device via pattern filter, then print result -- */

static void probe_and_print(const char *device_path,
                            unsigned major_num, unsigned minor_num,
                            const char *pattern) {
	if (pattern) {
		char pattern_copy[64];
		strncpy(pattern_copy, pattern, sizeof(pattern_copy) - 1);
		pattern_copy[sizeof(pattern_copy) - 1] = 0;
		char *colon = strchr(pattern_copy, ':');
		if (colon) {
			*colon = 0;
			unsigned p_major = (unsigned)strtoul(pattern_copy, NULL, 10);
			const char *p_minor_str = colon + 1;
			if (p_major != major_num) return;
			if (strcmp(p_minor_str, "*") != 0) {
				unsigned p_minor = (unsigned)strtoul(p_minor_str, NULL, 10);
				if (p_minor != minor_num) return;
			}
		}
	}

	uint8_t uuid[16];
	int probe_type = PROBE_RESULT_NONE;
	if (probe_single_device(device_path, uuid, &probe_type)) {
		print_probe_device_result(device_path, major_num, minor_num, uuid, probe_type);
	}
}


/* -- scan /proc/partitions for block devices -- */

static void probe_linux_block_devices(const char *pattern) {
	FILE *pp = fopen("/proc/partitions", "r");
	if (!pp) {
#ifndef WINDHAM_ISOC
		print_error(_(
			"Cannot open /proc/partitions. This system may be running a GNU-like OS "
			"on a non-Linux kernel (e.g., WSL1, FreeBSD Linuxulator), or the procfs "
			"filesystem is not mounted. Mount procfs (\"mount -t proc proc /proc\") "
			"and ensure /dev is populated, then retry."));
#else
		print_error(_(
			"Cannot open /proc/partitions. This platform may not be running a Linux "
			"kernel, or procfs is unavailable. --probe-linux requires a Linux kernel "
			"with mounted procfs. Use --dir to probe a specific path instead."));
#endif
	}

	char line[256];
	fgets(line, sizeof(line), pp);
	fgets(line, sizeof(line), pp);

	while (fgets(line, sizeof(line), pp)) {
		unsigned major_num = 0, minor_num = 0;
		unsigned long blocks = 0;
		char name[128] = {0};

		if (sscanf(line, "%u %u %lu %127s", &major_num, &minor_num, &blocks, name) != 4) continue;

		if (major_num == 0) continue;
		if (name[0] == '\0') continue;

		char dev_path[256];
		snprintf(dev_path, sizeof(dev_path), "/dev/%s", name);

		probe_and_print(dev_path, major_num, minor_num, pattern);
	}
	fclose(pp);
}


void action_probe(const char *dir_path, bool probe_linux, const char *pattern) {
	if (probe_linux) {
		probe_linux_block_devices(pattern);
	} else if (dir_path) {
		probe_and_print(dir_path, 0, 0, pattern);
	}
}
