#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <windham_const.h>
#include <cJSON.h>

#include "srclib.c"

#define CHECK_DEVICE_TOPOLOGY(device_path, node, CODE_EXEC_IF_RET) \
   char * device_loc;                                                                \
   if (strcmp(device_path, "") != 0){                                                                \
      device_loc = malloc(strlen(device) + strlen(device_path"/") + 1); \
      sprintf(device_loc, device_path"/%s", device); \
   } else {                                                        \
      device_loc = device_path;                                                                \
	}                                                                \
   char ** parent = NULL;                                          \
   char ** child = NULL;\
   node = (char **) &device_loc; \
   char ** mount_points = NULL; \
   size_t parent_ret_len, child_ret_len, mount_points_len = 0; \
\
int retval = check_device_topology(&parent, &child, &mount_points, &parent_ret_len, &child_ret_len, &mount_points_len); \
if (strcmp(device_path, "") != 0){                                                                   \
	free(device_loc);                                                  \
}                                                                   \
if (retval == 0){                                                  \
CODE_EXEC_IF_RET                                                                   \
}\
check_device_topology_free(parent, mount_points, parent_ret_len, mount_points_len)


#define CHECK_DEVICE_TOPOLOGY_PRINT_ERROR(comp_var, CODE_CMP_COND, pri_arr, CODE_PRI_ONE_RETLEN, CODE_PRI_MUL_RETLEN) \
if (comp_var CODE_CMP_COND) {                                                                                         \
	if (comp_var == 1 || strcmp(#CODE_PRI_MUL_RETLEN, "(\"\")") == 0){\
		print_error_no_exit CODE_PRI_ONE_RETLEN; \
	} else {                                                                                                    \
		print_error_no_exit CODE_PRI_MUL_RETLEN;\
      for (size_t i = 0; i < comp_var; i++) {                                                       		\
         printf("\033[1;33m - %s\033[0m\n", ((char **)pri_arr)[i]); \
      }                                                                                                           \
   }                                                                                                          \
	longjmp(windham_exit, NMOBJ_windham_exit_error); \
}




#ifndef INCL_LIBLOOP
#define INCL_LIBLOOP

void init_libloop(){
	STR_device = calloc(1, sizeof(Device));
}

void init_device(const char * filename, bool make_loop_device, bool is_nofail) {
	if (access(filename, F_OK) != 0) {
		if (is_nofail) {
			exit(0);
		}
		print_error(_("File %s does not exist"), filename);
	}
	
	if (access(filename, R_OK) != 0) {
		print_error(_("Cannot read %s: insufficient permission."), filename);
	}
	if (access(filename, W_OK) != 0) {
		print_error(_("Cannot write to %s: insufficient permission."), filename);
	}
	
	struct stat buf;
	if (stat(filename, &buf) == -1) {
		perror("stat");
		exit(1);
	}
	if (!S_ISBLK(buf.st_mode) && make_loop_device){
			char *exec_dir[] = {"/sbin", "/usr/sbin", "/bin", "/usr/bin", NULL};
			char *dup_stdout = NULL;
			size_t dup_stdout_len = 0;
			int exec_ret_val = 0;
			
			printf(_("Non block device deleted, creating loop.\n"));

			bool success = exec_name("losetup", exec_dir, &dup_stdout, &dup_stdout_len, &exec_ret_val, true, "-f", "--show", filename, NULL);
			if (!success || exec_ret_val != 0) {
				print_error(_("Failed to setup loop device for %s"), filename);
				
			}
			dup_stdout[dup_stdout_len - 1] = 0; // returns with /n

			STR_device->is_loop = true;
			STR_device->name = dup_stdout;
			STR_device->is_malloced_name = true;
	} else {
		STR_device->is_loop = false;
		STR_device->name = filename;
		STR_device->is_malloced_name = false;
	}

	if (make_loop_device || S_ISBLK(buf.st_mode)){
		int fd = open(STR_device->name, O_RDONLY);
		if (fd == -1) {
			perror("open");
			print_error(_("can not open loop device %s created from %s"), STR_device->name, filename);
		}
		size_t size;
		if (ioctl(fd, BLKGETSIZE, &size) == -1) {
			close(fd);
			print_error(_("can not get block size from block device %s created from %s, reason: %s"), STR_device->name, filename, strerror(errno));
		}
		close(fd);
		STR_device->block_size = size;
	} else {
		STR_device->block_size = 0;
	}
}

void free_loop(const char * name){
	char *exec_dir[] = {"/sbin", "/usr/sbin", "/bin", "/usr/bin", NULL};
	int exec_ret_val = 0;
	
	bool success = exec_name("losetup", exec_dir, NULL, NULL, &exec_ret_val, true, "-d", name, NULL);
	if (!success || exec_ret_val != 0) {
		print_warning(_("Failed to free loop device %s. Please run \"losetup -d %s\" manually."), name, name);
	}
}

void fin_device(){
	if (STR_device->is_loop == true){
		free_loop(STR_device->name);
	}
	if (STR_device->is_malloced_name == true){
		free((void *)STR_device->name);
	}
}



int check_device_topology(char *** parent, char *** child, char *** mount_points, size_t * parent_ret_len, size_t * child_ret_len, size_t * mount_points_len){
	assert(!(*parent && *child)); assert(!*mount_points);
	char *exec_dir[] = {"/bin", "/usr/bin", "/sbin", "/usr/sbin", NULL};
	char *dup_stdout = NULL;
	size_t dup_stdout_len = 0;
	int exec_ret_val = 0;
	bool success;

	if (*parent){
		success = exec_name("lsblk", exec_dir, &dup_stdout, &dup_stdout_len, &exec_ret_val, true, **parent, "-J", "-p", NULL);
	} else {
		success = exec_name("lsblk", exec_dir, &dup_stdout, &dup_stdout_len, &exec_ret_val, true, **child, "-s", "-J", "-p", NULL);
	}
	if (!success){
		print_error(_("Cannot call \"lsblk\". please make sure that the util-linux has installed."));
	}
	if (exec_ret_val != 0) {
		print_warning(_("Cannot determine device topology."));
		*parent_ret_len = *child_ret_len = *mount_points_len = 0;
		return 1;
	}

	cJSON *json = cJSON_Parse(dup_stdout);
	free(dup_stdout);
	cJSON * json_blockdevice = cJSON_GetObjectItemCaseSensitive(json, "blockdevices");
	cJSON * json_device = cJSON_GetArrayItem(json_blockdevice, 0);
	cJSON * json_mountpoints = cJSON_GetObjectItemCaseSensitive(json_device, "mountpoints");
	bool is_mountpoints_null = cJSON_IsNull(cJSON_GetArrayItem(json_mountpoints, 0));

	if (is_mountpoints_null){
		*mount_points = NULL; 
		*mount_points_len = 0;
	} else {
		*mount_points_len = cJSON_GetArraySize(json_mountpoints);
		*mount_points = malloc(sizeof(char *) * *mount_points_len);
		for (size_t i = 0; i < *mount_points_len; i ++){
			char * temp = cJSON_GetStringValue(cJSON_GetArrayItem(json_mountpoints, (int)i));
			(*mount_points)[i] = strdup(temp);
		}
	}

	char ** children_string;
	if (cJSON_HasObjectItem(json_device, "children")){
		cJSON * json_children_array = cJSON_GetObjectItemCaseSensitive(json_device, "children"); 
		size_t json_children_array_size = cJSON_GetArraySize(json_children_array);
		children_string = malloc(json_children_array_size);

		for (size_t i = 0; i < json_children_array_size; i ++){
			cJSON * json_children = cJSON_GetArrayItem(json_children_array, (int) i);
			char * json_children_name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json_children, "name"));
			children_string[i] = strdup(json_children_name);
		}
		if (*parent){
			*child = children_string;
			*child_ret_len = json_children_array_size;
		} else {
			*parent = children_string;
			*parent_ret_len = json_children_array_size;
		}
	} else {
		*parent_ret_len = *child_ret_len = 0;
	}
	cJSON_free(json);
	return 0;
}


void check_device_topology_free(char ** arr1, char ** arr2, size_t len_arr1, size_t len_arr2){
	for (size_t i = 0; i < len_arr1; i++){
		free(arr1[i]);
	}
	free(arr1);
		for (size_t i = 0; i < len_arr2; i++){
		free(arr2[i]);
	}
	free(arr2);
}

#endif