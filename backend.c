//
// Created by level-128 on 8/24/23.
//

#include <sys/sysinfo.h>
#include <sys/stat.h>

struct SystemInfo {
    unsigned long free_ram;
    unsigned long total_swap;
    unsigned long free_swap;
    long num_processors;
};


void is_running_as_root() {
    if (getuid() != 0){
        print_error("The program requires root permission. try adding 'sudo', or using argument '--no-admin' if the target is accessible without root permission");
    }
}

struct SystemInfo get_system_info() {
    struct sysinfo info;
    struct SystemInfo sys_info;


    if (sysinfo(&info) == -1) {
        perror("sysinfo");
        exit(EXIT_FAILURE);
    }


    long num_processors = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_processors == -1) {
        perror("sysconf");
        exit(EXIT_FAILURE);
    }

    sys_info.free_ram = info.freeram / 1024;
    sys_info.total_swap = info.totalswap;
    sys_info.free_swap = info.freeswap;
    sys_info.num_processors = num_processors;

    return sys_info;
}

int check_file(const char *filename) {
    // 检查文件是否存在
    if (access(filename, F_OK) != 0) {
        perror("Error: File does not exist");
        return 1;
    }

    // 检查读写权限
    if (access(filename, R_OK) != 0) {
        perror("Error: Cannot read file");
        return 1;
    }
    if (access(filename, W_OK) != 0) {
        perror("Error: Cannot write to file");
        return 1;
    }

    // 获取文件大小
    struct stat file_stat;
    if (stat(filename, &file_stat) != 0) {
        perror("Error: Cannot get file size");
        return 1;
    }
    off_t file_size = file_stat.st_size; // 获取文件大小，单位是字节

    // 检查文件大小是否大于 4 KiB
    if (file_size <= 4096) {
        printf("Error: File size is less than or equal to 4 KiB\n");
        return 1;
    }

    printf("File has read and write permissions and is greater than 4 KiB.\n");
    return 0;
}