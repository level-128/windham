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
	size_t unenc_metadata_sector;
	size_t enc_data_start_sector;
	size_t enc_data_size;
	size_t sector_size;
} Dynenc_param;

void dynesc_calc_param(Dynenc_param * param, size_t device_block_count, size_t sector_size){
	const size_t device_size = device_block_count * 512;
	param->disk_size = device_size;
	param->unenc_data_start = 0;
	param->unenc_data_size = FLOOR_MULT(((device_size - (4096 + sector_size)) / (sector_size + 4)) * sector_size, sector_size);
	param->unenc_hash_start = param->unenc_data_size + sector_size;
	param->unenc_hash_size = param->unenc_data_size / (sector_size / 4);
	param->unenc_metadata_sector = device_size - 4096;
	param->enc_data_start_sector = sector_size;
	param->enc_data_size = param->unenc_data_size;
	param->sector_size = sector_size;
}

uint8_t * map_disk(const char * disk_name, size_t device_block_count){
	int fd;
	uint8_t *map;
	
	fd = open(disk_name, O_RDWR);
	if (fd == -1) {
		perror("Error opening file");
		exit(EXIT_FAILURE);
	}
	
	map = mmap(NULL, device_block_count * 512, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("Error mmapping the file");
		close(fd);
		exit(EXIT_FAILURE);
	}
	return map;
}

void hash_one_sector(blake3_hasher * blake_header, Dynenc_param param, const uint8_t unenc_data[param.sector_size], uint8_t hash_val[4]){
	blake3_hasher_reset(blake_header);
	blake3_hasher_update(blake_header, unenc_data, param.sector_size);
	blake3_hasher_finalize(blake_header, hash_val, 4);
}

void create_disk_hash(Dynenc_param param, uint8_t unenc_map[param.disk_size]){
	blake3_hasher blake_header;
	blake3_hasher_init(&blake_header);
	for (size_t i = param.unenc_data_start, j = param.unenc_hash_start; i < param.unenc_data_size; i += param.sector_size, j += 4){
		hash_one_sector(&blake_header, param, unenc_map + i, unenc_map + j);
	}
}

void copy_disk(Dynenc_param param, uint8_t disk_map[param.disk_size], uint8_t enc_map[param.disk_size]){
	for (size_t i = param.unenc_data_start + param.unenc_data_size - param.sector_size; i > param.unenc_data_start; i -= param.sector_size){
		memcpy(&enc_map[i + param.sector_size], &disk_map[i], param.sector_size);
		msync(&enc_map[i + param.sector_size], param.sector_size, MS_SYNC);
		msync(&disk_map[i + param.sector_size], param.sector_size, MS_SYNC);
	}
	// last sector;
	memcpy(&enc_map[param.unenc_data_start + param.sector_size], &disk_map[param.unenc_data_start], param.sector_size);
	msync(&enc_map[param.unenc_data_start + param.sector_size], param.sector_size, MS_SYNC);
	msync(&disk_map[param.unenc_data_start + param.sector_size], param.sector_size, MS_SYNC);
	
	// header
	fill_secure_random_bits(&disk_map[sizeof(Data)], param.sector_size - sizeof(Data));
	memcpy(&disk_map[0], &disk_map[param.unenc_metadata_sector], 4096);
	msync(&disk_map[param.unenc_data_start], param.sector_size, MS_SYNC);
	
	// old header
	fill_secure_random_bits(&disk_map[param.unenc_hash_start + param.unenc_hash_size], param.disk_size - param.unenc_hash_start - param.unenc_hash_size);
	msync(&disk_map[param.unenc_hash_start + param.unenc_hash_size], param.disk_size - param.unenc_hash_start - param.unenc_hash_size, MS_SYNC);
}


void write_test(uint8_t * mapped, size_t device_size){
	for (size_t i = 0; i < device_size; ++i) {
		mapped[i] = (uint8_t)(i % 256);
	}
}

