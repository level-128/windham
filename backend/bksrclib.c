#pragma once

#include <windham_const.h>
#include <blkid/blkid.h>

#include "../library_intrnlsrc/srclib.c"
#include "../library_intrnlsrc/enclib.c"
#include "../library_intrnlsrc/kerkey.c"
#include "../library_intrnlsrc/dynenc.c"
#include "../library_intrnlsrc/mapper.c"
#include "../library_intrnlsrc/libloop.c"


#define OPERATION_BACKEND_UNENCRYPT_HEADER    \
[[maybe_unused]] int unlocked_slot = get_master_key(data, master_key, key, device, target_unlock_slot, max_unlock_mem, max_unlock_time); \
                                              \
if (lock_or_unlock_metadata_using_master_key(&data, master_key) == false) {\
print_error(key.key_type != EMOBJ_key_file_type_masterkey ? _("This key has been revoked.") : _("Wrong master key."));\
}                                  \
operate_all_keyslots_using_keyslot_key_in_metadata(data.keyslots, data.metadata.keyslot_key, data.master_key_mask, true); /* open all key slots */ \
bool revoked_untagged_slot[KEY_SLOT_COUNT];              \
check_master_key_and_slots_revoke(&data, revoked_untagged_slot);\
for (int i = 0; i < KEY_SLOT_COUNT; i++){                \
if (revoked_untagged_slot[i] == true){     \
print_warning(_("Slot %i on device %s have been revoked without using the password."), i, device);                    \
}}                                  \

#define OPERATION_LOCK_AND_WRITE \
assign_new_header_iv(&data, is_assign_new_head);\
operate_all_keyslots_using_keyslot_key_in_metadata(data.keyslots, data.metadata.keyslot_key, data.master_key_mask, false);\
lock_or_unlock_metadata_using_master_key(&data, master_key);\
write_header_to_device(&data, device, offset);

#define PARAMS_FOR_KEY Key key, uint8_t master_key[32], int target_unlock_slot, uint64_t max_unlock_mem, double max_unlock_time


// supported crypt
char * crypt_list[] = {"aes", "twofish", "serpent", NULL};
char * chainmode_list[] = {"cbc", "xts", "ecb", NULL};
char * iv_list[] = {"plain64", "plain64be", "essiv", "eboiv", NULL};



void operate_header_on_device(Data * data, const char * device, int64_t offset, bool is_read){
	int fp;
	ssize_t result;
	
	fp = open(device, O_DSYNC | (is_read ? O_RDONLY : O_WRONLY));
	if (fp == 0) {
		print_error(_("Failed to open %s: %s"), device, strerror(errno));
	}
	
	if (offset < 0) {
		lseek(fp, offset, SEEK_END);
	} else {
		lseek(fp, offset, SEEK_SET);
	}
	
	if (is_read){
		result = read(fp, data, sizeof(Data));
		if (result != sizeof(Data)) {
			print_error(_("Failed to read %s: %s\""), device, strerror(errno));
		}
	} else {
		result = write(fp, data, sizeof(Data));
		if (result != sizeof(Data)) {
			print_error(_("Failed to write %s: %s\""), device, strerror(errno));
		}
	}
	close(fp);
}


void write_header_to_device(const Data * data, const char * device, int64_t offset) {
	operate_header_on_device((Data *) data, device, offset, false);
}

void get_header_from_device(Data * data, const char * device, int64_t offset) {
	operate_header_on_device((Data *) data, device, offset, true);
}


struct SystemInfo {
	unsigned long free_ram;
	unsigned long free_swap;
	unsigned long total_ram;
};
struct SystemInfo sys_info;

void get_system_info() {
	FILE * meminfo = fopen("/proc/meminfo", "r");
	if (meminfo == NULL) {
		print_warning(_("Failed to read system information. Can not determine adequate memory size (or memory limit) for key derivation."));
		sys_info.free_ram = ULONG_MAX;
		sys_info.free_swap = ULONG_MAX;
		return;
	}
	
	char line[256];
	unsigned long memFree = 0;
	unsigned long memTotal = 0;
	unsigned long cached = 0;
	unsigned long swapFree = 0;
	
	while (fgets(line, sizeof(line), meminfo)) {
		if (strncmp(line, "MemFree:", 8) == 0) {
			sscanf(line, "%*s %lu", &memFree);
		} else if (strncmp(line, "MemTotal:", 9) == 0) {
			sscanf(line, "%*s %lu", &memTotal);
		} else if (strncmp(line, "Cached:", 7) == 0) {
			sscanf(line, "%*s %lu", &cached);
		} else if (strncmp(line, "SwapFree:", 9) == 0) {
			sscanf(line, "%*s %lu", &swapFree);
		}
	}
	
	sys_info.free_ram = memFree + cached;
	sys_info.free_swap = swapFree;
	sys_info.total_ram = memTotal;
	
	fclose(meminfo);
}


size_t check_target_mem(size_t target_mem, bool is_encrypt) {
	if (target_mem == 0) {
		if ((double) sys_info.free_ram / (double) sys_info.total_ram < 0.3) {
			print_warning(_("The system is low on memory (< 30%%). It is recommended to designate a larger allowed memory to utilize the system swap space via parameter \"%s\"."),
			              is_encrypt ? "--target-memory" : "--max-unlock-memory");
		}
		return sys_info.free_ram;
	}
	
	if (sys_info.free_ram < target_mem) {
		
		if ((sys_info.free_swap + sys_info.free_ram) > target_mem) {
			print_warning(_("using swap space for Key derivation function. This is potentially insecure because unencrypted swap space may provide hints to the master key."));
		} else {
			size_t new_target_mem = sys_info.free_swap + sys_info.free_ram - (1 << 16);
			if (is_encrypt) {
				ask_for_conformation(_("The RAM and swap are not enough to perform the suggested encryption parameters. Adjusted the max RAM consumption for Key derivation function"
				                       " from %lu (KiB) to %lu (KiB). This may degrade security, continue?"), target_mem, new_target_mem);
			} else {
				print_warning(_("Adjusted the requested max RAM consumption from %lu (KiB) to %lu (KiB) because of insufficient memory. "
				                "If your computer has less available memory than the computer who created the encryption target, you may not successfully decrypt this target. Consider adding more "
				                "swap spaces as a workaround."), target_mem, new_target_mem);
			}
			return new_target_mem;
		}
	}
	return target_mem;
}

typedef enum{
	NMOBJ_MAPPER_DEVSTAT_DECOY,
	NMOBJ_MAPPER_DEVSTAT_SUSP,
	NMOBJ_MAPPER_DEVSTAT_CONV,
	NMOBJ_MAPPER_DEVSTAT_NORM
} ENUM_MAPPER_DEVSTAT;

ENUM_MAPPER_DEVSTAT detect_device_status(const char * device, bool is_decoy){
	uint8_t content_head[16], content_end_head[16];
	int fp = open(device, O_RDONLY);
	if (fp == 0) {
		print_error(_("can not open device %s"), device);
	}
	read(fp, content_head, sizeof(content_head));
	
	lseek(fp, -4096, SEEK_END);
	read(fp, content_end_head, sizeof(content_end_head));
	
	close(fp);
	if (memcmp(content_end_head, head_converting, sizeof(head_converting)) == 0){
		return NMOBJ_MAPPER_DEVSTAT_CONV;
	} else if (memcmp(content_head, head, sizeof(head)) == 0){
		return NMOBJ_MAPPER_DEVSTAT_SUSP;
	}

    if (is_decoy){
        return NMOBJ_MAPPER_DEVSTAT_DECOY;
    } else {
        blkid_probe probe = blkid_new_probe_from_filename(device);
        if (!probe) {
            print_error(_("can not open device %s"), device);
        }

        if (blkid_do_probe(probe) == -1) {
            blkid_free_probe(probe);
            print_error(_("Filesystem probe failed for %s."), device);
        }
        const char *fstype = "";
        size_t len;

        if (blkid_probe_lookup_value(probe, "TYPE", &fstype, &len) == 0) {
            print_error_no_exit(
                    _("Device %s contains active %s filesystem. Cannot open %s. If the device contains a decoy partition, use \"--decoy\" to bypass filesystem check."),
                    device, fstype, device);
            blkid_free_probe(probe);
            longjmp(windham_exit, NMOBJ_windham_exit_error);
        }
        blkid_free_probe(probe);
        return NMOBJ_MAPPER_DEVSTAT_NORM;
    }
}

ENUM_MAPPER_DEVSTAT frontend_read_header_ret_ENUM_MAPPER_DEVSTAT(const char * device, Data * unini_data, int64_t * unini_offset, bool is_decoy) {
	ENUM_MAPPER_DEVSTAT ret = detect_device_status(device, is_decoy);
	switch (ret) {
		case NMOBJ_MAPPER_DEVSTAT_SUSP:
			*unini_offset = 0;
			if (is_decoy == true) {
				print_error(_("Unable to set \"--decoy\" for suspended device."));
			}
			break;
		case NMOBJ_MAPPER_DEVSTAT_CONV:
			*unini_offset = -4096;
			if (is_decoy == true) {
				print_error(_("Unable to set \"--decoy\" for device during conversion."));
			}
			break;
		case NMOBJ_MAPPER_DEVSTAT_NORM:
            *unini_offset = 0;
            break;
        case NMOBJ_MAPPER_DEVSTAT_DECOY:
            print_warning(_("Unlocking %s assuming decoy partition exits"), device);
            *unini_offset = -4096;
            break;
    }
	get_header_from_device(unini_data, device, *unini_offset);
	return ret;
}


void decide_start_and_end(const char * device, size_t device_block_count, size_t * start_sector, size_t * end_sector, size_t block_size, bool is_decoy) {
	
	size_t safe_node = (0x78000b + (16 << 20)) / 512; // safe sector
	if (is_decoy) {
		if (device_block_count % (block_size / 512) != 0) {
			print_error(_("Impossible to create a decoy scheme since the size of the crypt device is not the integer multiple of the sector size."));
		}
		if (device_block_count < (128 << 20) / 512) {
			print_error(_("Device %s is too small to deploy decoy partition; Windham requires at least %i MiB."), device, 128);
		}
		*end_sector = device_block_count - 8;
		*start_sector = (device_block_count - safe_node) * 4 / 12 + safe_node;
	} else {
		if (device_block_count % (block_size / 512) != 0) {
			ask_for_conformation(_("The size of the crypt device is not the integer multiple of the sector size. You may experience degraded performance."));
		}
		if (device_block_count < (8 << 10) / 512) {
			print_error(_("Device %s is too small; Windham requires at least %i KiB."), device, 8);
		}
		*start_sector = 8;
		*end_sector = device_block_count - device_block_count % (block_size / 512);
	}
	return;
}