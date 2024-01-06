#include "windham_const.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <blake3.h>
#include <linux/fs.h>
#include <ext2fs/ext2fs.h> // libext2fs-devel
#include <libprogstats.h>

#ifndef INCL_DYNENC
#define INCL_DYNENC

#include "enclib.c"

#define CEIL_MULT(x, y) (((x) + (y) - 1) / (y) * (y))

#define FLOOR_MULT(x, y) ((x) / (y) * (y))

typedef struct {
	size_t disk_size;
	size_t unenc_data_start;
	size_t unenc_data_size;
	size_t unenc_hash_start;
	size_t unenc_hash_size;
	size_t unenc_metadata;
	size_t enc_data_start;
	size_t enc_data_size;
	size_t section_size;
} Dynenc_param;

void dynesc_calc_param(Dynenc_param * param, size_t device_sector_count, size_t section_size) {
	const size_t device_size = device_sector_count * 512;
	param->disk_size = device_size;
	param->unenc_data_start = 0;
	param->unenc_data_size = FLOOR_MULT(((device_size - (4096 + section_size)) / (section_size + 4)) * section_size, section_size);
	param->unenc_hash_start = param->unenc_data_size + section_size;
	param->unenc_hash_size = param->unenc_data_size / (section_size / 4);
	param->unenc_metadata = device_size - 4096;
	param->enc_data_start = section_size;
	param->enc_data_size = param->unenc_data_size;
	param->section_size = section_size;
}

uint8_t * map_disk(const char * disk_name, size_t device_block_count, bool is_write) {
	int fd;
	uint8_t * map;
	
	fd = open(disk_name, O_RDWR);
	if (fd == -1) {
		perror("Error opening file");
		exit(EXIT_FAILURE);
	}
	
	map = mmap(NULL, device_block_count * 512, is_write ? PROT_READ | PROT_WRITE : PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("Error mmapping the file");
		close(fd);
		exit(EXIT_FAILURE);
	}
	return map;
}

void unmap_disk(uint8_t * mapped_device, size_t device_block_cnt) {
	munmap(mapped_device, device_block_cnt * 512);
}

void hash_one_sector(blake3_hasher * blake_header, Dynenc_param param, const uint8_t unenc_data[param.section_size], uint8_t hash_val[4]) {
	blake3_hasher_reset(blake_header);
	blake3_hasher_update(blake_header, unenc_data, param.section_size);
	blake3_hasher_finalize(blake_header, hash_val, 4);
}

void create_disk_hash(Dynenc_param param, const char * device) {
	int fd = open(device, O_RDWR);
	if (fd == -1) {
		perror("Error opening file");
		exit(EXIT_FAILURE);
	}
	
	blake3_hasher blake_header;
	blake3_hasher_init(&blake_header);
	
	uint8_t * buffer = malloc(param.section_size);
	
	progressbar * create_disk_hash_progressbar = progressbar_new(_("Creating disk hash:"), param.unenc_data_size / param.section_size);
	
	for (size_t i = param.unenc_data_start, j = param.unenc_hash_start;
	     i < param.unenc_data_size;
	     i += param.section_size, j += 4) {
		
		lseek(fd, i, SEEK_SET);
		
		if (read(fd, buffer, param.section_size) == -1) {
			print_error(_("Failed to create disk hash: %s. Your data is safe and the disk is still accessible. You can restart the conversion at any time."), strerror(errno));
		}
		
		hash_one_sector(&blake_header, param, buffer, buffer);
		
		lseek(fd, j, SEEK_SET);
		
		if (write(fd, buffer, 4) == -1) {
			print_error(_("Failed to create disk hash: %s. Your data is safe and the disk is still accessible. You can restart the conversion at any time."), strerror(errno));
		}
		progressbar_inc(create_disk_hash_progressbar);
	}
	free(buffer);
	fsync(fd);
	progressbar_finish(create_disk_hash_progressbar);
	close(fd);
}

uint64_t check_disk_hash(Dynenc_param param, const char * device) {
	uint8_t * unenc_mmap = map_disk(device, param.disk_size / 512, false);
	blake3_hasher blake_header;
	blake3_hasher_init(&blake_header);
	size_t sector_start = 0;
	size_t sector_stop = param.unenc_data_size / param.section_size;
	uint8_t hash_val[4];
	while (true) {
		if (sector_start == sector_stop) {
			unmap_disk(unenc_mmap, param.disk_size / 512);
			if (sector_start == 0){
				return UINT64_MAX;
			} else {
				return (sector_start - 1) * param.section_size + param.unenc_data_start;
			}
		}
		size_t cur_sector = (sector_start + sector_stop) / 2;
		hash_one_sector(&blake_header, param, &unenc_mmap[cur_sector * param.section_size + param.unenc_data_start], hash_val);
		if (memcmp(hash_val, &unenc_mmap[cur_sector * 4 + param.unenc_hash_start], 4) != 0) {
			sector_stop = cur_sector;
		} else {
			sector_start = cur_sector + 1;
		}
	}
}

void copy_disk(Dynenc_param param, const char * device, const char * enc_device, uint64_t start_point) {
	int count = 0;
	progressbar * copy_disk_progressbar;
	START:
	{}
	int fd = open(device, O_RDONLY);
	int fd_enc = open(enc_device, O_RDWR);
	
	if (fd == -1 || fd_enc == -1) {
		if (count++ < 10) {
			sleep(1);
			goto START;
		}
		perror("Error opening file");
		if (fd != -1) { close(fd); }
		if (fd_enc != -1) { close(fd_enc); }
		exit(EXIT_FAILURE);
	}
	
	uint8_t * buffer = malloc(param.section_size);

	if (start_point == UINT64_MAX){
		copy_disk_progressbar = progressbar_new(_("Moving sections:"), param.unenc_data_size / param.section_size);
		start_point = param.unenc_data_start + param.unenc_data_size - param.section_size;
	} else {
		copy_disk_progressbar = progressbar_new(_("Recovering progress:"), (start_point - param.unenc_data_start + param.section_size) / param.section_size);
		start_point = start_point;
	}
	for (; start_point != param.unenc_data_start - param.section_size /* Overflow of unsigned integer is a well defined behaviour*/; start_point -= param.section_size) {
		
		if (lseek(fd, (off_t) start_point, SEEK_SET) == -1 || read(fd, buffer, param.section_size) == -1) {
			print_error(_("Error converting the disk: %s. The disk is now left in an inconsistent state. Use \"windham Open <target>\" to fix the partition."), strerror(errno));
		}
		
		if (lseek(fd_enc, (off_t) start_point, SEEK_SET) == -1 || write(fd_enc, buffer, param.section_size) == -1) {
			print_error(_("Error converting the disk: %s. The disk is now left in an inconsistent state. Use \"windham Open <target>\" to fix the partition."), strerror(errno));
		}
		fsync(fd_enc);
		progressbar_inc(copy_disk_progressbar);
	}
	progressbar_finish(copy_disk_progressbar);
	
	free(buffer);
	close(fd);
	close(fd_enc);
}


__attribute__((unused)) void write_test(char * device) {
	size_t device_block_cnt = get_device_block_cnt(device);
	int fd = open(device, O_WRONLY);
	if (fd == -1) {
		perror("Error opening device");
		return;
	}
	
	uint8_t * buffer = (uint8_t *) malloc(512);
	if (!buffer) {
		perror("Failed to allocate memory");
		close(fd);
		return;
	}
	
	for (size_t i = 0; i < device_block_cnt; ++i) {
		for (size_t j = 0; j < 512; ++j) {
			buffer[j] = (uint8_t) (j % 256);
		}
		ssize_t written = write(fd, buffer, 512);
		if (written != 512) {
			perror("Error writing to device");
			break;
		}
	}
	
	free(buffer);
	fsync(fd);
	close(fd);
}


void shrink_disk(Dynenc_param param, const char * device) {
	char * exec_dir[] = {"/sbin", "/usr/sbin", NULL};
	char * dup_stdout = NULL;
	size_t dup_stdout_len = 0;
	int exec_ret_val;
	
	printf(_("Shrinking the filesystem on %s from %lu sectors to %lu sectors...\n"), device, param.disk_size / 512, param.unenc_data_size / 512);
	
	if (exec_name("blkid", exec_dir, &dup_stdout, &dup_stdout_len, &exec_ret_val, true, "-o", "value", "-s", "TYPE", device, NULL) == false) {
		print_warning(_("Failed to identify the partition type, cannot run blkid."));
	} else if (exec_ret_val != 0) {
		print_warning(_("Failed to identify the partition type"));
	} else if (strcmp(dup_stdout, "ext4\n") == 0) {
		free(dup_stdout);
		
		// resize2fs /dev/sda1
		char argsize[20];
		sprintf(argsize, "%lus", param.unenc_data_size / 512);
		if (exec_name("resize2fs", exec_dir, &dup_stdout, &dup_stdout_len, &exec_ret_val, true, device, argsize, NULL) == false) {
			print_warning(_("Failed to adjust the size of the partition, resize2fs does not exist."));
		} else if (exec_ret_val != 0) {
			print_warning(_("Failed to adjust the size of the partition, reason:\n%s"), dup_stdout);
		} else {
			printf(_(" Done\n"));
			free(dup_stdout);
			return;
		}
	}
	free(dup_stdout);
	ask_for_conformation(_("Windham cannot shrink the given partition: %s. The partition need to be shrank to %lu sectors before proceed. You need to perform the shrinking manually before "
	                     "continue."), device, param.unenc_data_size / 512);
}

#endif