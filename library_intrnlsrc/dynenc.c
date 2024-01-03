#include "windham_const.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <blake3.h>

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
	
	uint8_t *buffer = malloc(param.section_size);
	
	for (size_t i = param.unenc_data_start, j = param.unenc_hash_start;
	     i < param.unenc_data_size;
	     i += param.section_size, j += 4) {
		
		// Set file pointer to the start of the sector to be read
		lseek(fd, i, SEEK_SET);
		
		// Read the sector data into buffer
		if (read(fd, buffer, param.section_size) == -1) {
			perror("Error reading file");
			break;
		}
		
		// Hash the data
		hash_one_sector(&blake_header, param, buffer, buffer);
		
		// Set file pointer to the position where hash is to be written
		lseek(fd, j, SEEK_SET);
		
		// Write the hash value to the disk
		if (write(fd, buffer, 4) == -1) {
			perror("Error writing to file");
			break;
		}
	}
	
	free(buffer);
	fsync(fd);
	close(fd);
}

size_t check_disk_hash(Dynenc_param param, const char * device, size_t block_count){
	uint8_t * unenc_mmap = map_disk(device, block_count, false);
	blake3_hasher blake_header;
	blake3_hasher_init(&blake_header);
	size_t sector_start = 0;
	size_t sector_stop = param.unenc_data_size / param.section_size;
	uint8_t hash_val[4];
	while (true){
		if (sector_start == sector_stop){
			unmap_disk(unenc_mmap, block_count);
			return sector_start * param.section_size + param.unenc_data_start;
		}
		size_t cur_sector = (sector_start + sector_stop) / 2;
		hash_one_sector(&blake_header, param, &unenc_mmap[cur_sector * param.section_size + param.unenc_data_start], hash_val);
		if (memcmp(hash_val, &unenc_mmap[cur_sector * 4 + param.unenc_hash_start], 4) != 0){
			sector_stop = cur_sector;
		} else {
			sector_start = cur_sector + 1;
		}
	}
}

void copy_disk(Dynenc_param param, const char * device, const char * enc_device) {
	int count = 0;
	START:{}
	int fd = open(device, O_RDONLY);
	int fd_enc = open(enc_device, O_RDWR);
	
	if (fd == -1 || fd_enc == -1) {
		if (count++ < 10){
			sleep(1);
			goto START;
		}
		perror("Error opening file");
		if (fd != -1) close(fd);
		if (fd_enc != -1) close(fd_enc);
		exit(EXIT_FAILURE);
	}
	
	uint8_t *buffer = malloc(param.section_size);
	if (buffer == NULL) {
		perror("Error allocating buffer");
		close(fd);
		close(fd_enc);
		exit(EXIT_FAILURE);
	}
	
	
	for (size_t i = param.unenc_data_start + param.unenc_data_size - param.section_size; i > param.unenc_data_start; i -= param.section_size) {
		
		if (lseek(fd, i, SEEK_SET) == -1 || read(fd, buffer, param.section_size) == -1) {
			perror("Error reading unencrypted disk");
			break;
		}
		
		if (lseek(fd_enc, i, SEEK_SET) == -1 || write(fd_enc, buffer, param.section_size) == -1) {
			perror("Error writing to encrypted disk");
			break;
		}
		fsync(fd_enc);
	}
	
	// last sector
	if (lseek(fd, param.unenc_data_start, SEEK_SET) != -1 && read(fd, buffer, param.section_size) != -1) {
		if (lseek(fd_enc, param.unenc_data_start, SEEK_SET) == -1 || write(fd_enc, buffer, param.section_size) == -1) {
			perror("Error writing last sector to encrypted disk");
		}
	} else {
		perror("Error reading last sector of unencrypted disk");
	}
	fsync(fd_enc);
	
	free(buffer);
	close(fd);
	close(fd_enc);
}



__attribute__((unused)) void write_test(char *device) {
	size_t device_block_cnt = get_device_block_cnt(device); // 假设这个函数返回设备的块数
	int fd = open(device, O_WRONLY); // 打开设备文件以进行写操作
	if (fd == -1) {
		perror("Error opening device");
		return;
	}
	
	uint8_t *buffer = (uint8_t *)malloc(512); // 分配一个块大小的缓冲区
	if (!buffer) {
		perror("Failed to allocate memory");
		close(fd);
		return;
	}
	
	for (size_t i = 0; i < device_block_cnt; ++i) {
		for (size_t j = 0; j < 512; ++j) {
			buffer[j] = (uint8_t)(j % 256);
		}
		ssize_t written = write(fd, buffer, 512); // 写入一个块
		if (written != 512) {
			perror("Error writing to device");
			break;
		}
	}
	
	free(buffer);
	fsync(fd);
	close(fd);
}


void shrink_disk(Dynenc_param param, const char * device){
	char * exec_dir[] = {"/sbin", "/usr/sbin", NULL};
	char * dup_stdout = NULL;
	size_t dup_stdout_len = 0;
	int exec_ret_val;
	char param_block_size[20];
	snprintf(param_block_size, 20, "%lus", param.unenc_data_size / 512);//blkid -o value -s TYPE /dev/loop1
	
	if (exec_name("blkid", exec_dir, &dup_stdout, &dup_stdout_len, &exec_ret_val, true, "-o", "value", "-s", "TYPE", device, NULL) == false){
		print_warning(_("Failed to identify the partition type, cannot run blkid."));
	} else if (exec_ret_val != 0){
		print_warning(_("Failed to identify the partition type"));
	} else if (strcmp(dup_stdout, "ext4\n") == 0){
		free(dup_stdout);
		if (exec_name("resize2fs", exec_dir, &dup_stdout, &dup_stdout_len, &exec_ret_val, true, device, param_block_size, NULL) == false){
			if (errno == ENOENT){
				print_warning(_("Failed to resize the partition, make sure that \"resize2fs\" has installed"));
			} else {
				print_warning(_("Failed to resize the partition"));
			}
		} else if (exec_ret_val != 0){
			print_warning(_("Failed to resize %s:\n%s"), device, dup_stdout);
		} else {
			free(dup_stdout);
			return;
		}
		free(dup_stdout);
	}
	ask_for_conformation("Windham cannot shrink the given partition: %s. The partition need to be shrank to %lu sectors before proceed. You need to perform the shrinking manually before "
								"continue.", device, param.unenc_data_size / 512);
}
