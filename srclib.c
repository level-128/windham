#include <inttypes.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <spawn.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

#ifndef _
#define _(x) x
#endif

#define swap(x,y) do \
   { assert(sizeof(x) == sizeof(y)); \
	unsigned char tmp_var[(signed)sizeof(x)]; \
     memcpy(tmp_var,&(y),sizeof(x)); \
     memcpy(&(y),&(x),sizeof(x)); \
     memcpy(&(x),tmp_var,sizeof(x)); \
    } while(0)

#define var_(x) __temp_var_at_line##x
#define var__(x) var_(x)
#define tmp_var var__(__LINE__)


#define CV_VA_NUM_ARGS_HELPER(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, N, ...)    N
#define CV_VA_NUM_ARGS(...) CV_VA_NUM_ARGS_HELPER(__VA_ARGS__ __VA_OPT__(,) 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define p__get_types__(...) p__get_types_helper__(__VA_ARGS__ __VA_OPT__(,) 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define p__get_types_helper__(a, b, c, d, e, f, g, h, i, j, N, ...)   \
   argtype[0] = p__type__(a);                                         \
   argtype[1] = p__type__(b);                                         \
   argtype[2] = p__type__(c);                                         \
   argtype[3] = p__type__(d);                                         \
   argtype[4] = p__type__(e);                                         \
   argtype[5] = p__type__(f);                                         \
   argtype[6] = p__type__(g);                                         \
   argtype[7] = p__type__(h);                                         \
   argtype[8] = p__type__(i);                                         \
   argtype[9] = p__type__(j);

#define p__type__(x__)    \
      _Generic((x__),     \
       _Bool              \
       : T_BOOL,   \
       uint64_t           \
       : T_INT,    \
         int64_t          \
       : T_INT,    \
         uint32_t         \
       : T_INT,    \
         int32_t          \
       : T_INT,    \
         uint16_t         \
       : T_INT,    \
         int16_t          \
       : T_INT,    \
         uint8_t          \
       : T_INT,    \
         int8_t           \
       : T_INT,    \
         double           \
       : T_DOUBLE, \
         float            \
       : T_DOUBLE, \
         char *           \
       : T_CHAR,   \
		   const char *     \
       : T_CHAR,   \
         default          \
       : T_PTR)

bool print_enable;
bool print_verbose = false;

#define print(...) \
   if (print_enable){                \
   int tmp_var = CV_VA_NUM_ARGS(__VA_ARGS__);\
   p__get_types__(__VA_ARGS__);                   \
   p__expands_args(tmp_var, __VA_ARGS__);\
   p__print__(tmp_var);} while(0)



int debug_print_error_suppress = 0;

#define print_error(...) \
    if (debug_print_error_suppress){ \
	 printf("\033[1;33m%s: ", _("SUPPRESS_ERROR")); \
    printf(__VA_ARGS__);           \
    printf("\033[0m\n");   \
	 debug_print_error_suppress--;\
	 } else {                    \
    printf("\033[1;31m%s: ", _("ERROR")); \
    printf(__VA_ARGS__);           \
    printf("\033[0m\n");   \
    exit(EXIT_FAILURE);} while (false)

#define print_error_no_exit(...) \
    printf("\033[1;31m%s: ", _("ERROR")); \
    printf(__VA_ARGS__);           \
    printf("\033[0m\n")

#define print_warning(...) \
    printf("\033[1;33m%s: ", _("WARNING")); \
    printf(__VA_ARGS__);           \
    printf("\033[0m\n")

typedef enum {
	T_INT,
	T_DOUBLE,
	T_CHAR,
	T_PTR,
	T_BOOL,
} TYPE_T;

#pragma once

TYPE_T argtype[10];
void * arg_ptr[10];

void p__expands_args(int argcount, ...) {
	va_list p__tmp_va__;
	va_start(p__tmp_va__, argcount);
	for (int i = 0; i < argcount; i++) {
		arg_ptr[i] = va_arg(p__tmp_va__, void *);
	}
	va_end(p__tmp_va__);
}

void p__print_int(int64_t self) {
	printf("%"
	PRId64, self);
}

void p__print_double(double self) {
	printf("%.11g", self);
}

void p__print_char(const char * self) {
	printf("%s", self);
}

void p__print_bool(_Bool self) {
	printf(self ? "true" : "false");
}

void p__print_ptr(void * self) {
	printf("<%p>", self);
}

void p__print__(int argcount) {
	for (int i = 0; i < argcount; i++) {
		switch (argtype[i]) {
			case T_INT: {
				p__print_int((int64_t) arg_ptr[i]);
				break;
			}
			case T_CHAR: {
				p__print_char(arg_ptr[i]);
				break;
			}
			case T_DOUBLE: {
				union p__temp__void_to_double_cast__ {
					void * x;
					double y;
				};
				union p__temp__void_to_double_cast__ tmp_var; tmp_var.x = arg_ptr[i]; p__print_double(tmp_var.y);
				break;
			}
			case T_BOOL: {
				p__print_bool(arg_ptr[i]);
				break;
			}
			case T_PTR: {
				p__print_ptr(arg_ptr[i]);
				break;
			}
		}
		printf(i == argcount - 1 ? "\n" : " ");
		
	}
}

void print_hex_array(size_t length, const uint8_t arr[length]) {
	for (size_t i = 0; i < length; ++i) {
		printf("%02x ", arr[i]);
	}
	printf("\n");
}

int64_t is_in_list(char * item, char * list[]) {
	int64_t i = 0;
	for (; list[i]; i++) {
		if (strcmp(item, list[i]) == 0) {
			return i;
		}
	}
	return -1;
}

void print_list(char * list[]) {
	for (int i = 0; list[i]; i++) {
		printf(" \"%s\"", list[i]);
	}
}

void print_ptr_poz(int pos, int msg) {
	if (print_verbose) {
		if (pos == -1) {
			printf(_("Unlock Progress for each keyslot:\n"));
			printf("\nSlot:     ");
			for (int i = 0; i < KEY_SLOT_COUNT; i++) {
				printf("%i       ", i);
			}
			printf("\nProgress: ");
			for (int i = 0; i < KEY_SLOT_COUNT; i++) {
				printf("0       ");
			}
		} else {
			printf("\033[%dG", pos * 8 + 11);
			
			if (msg > 0) {
				printf("%i", msg);
			} else if (msg == 0) {
				printf(_("\nUnlock complete. Slot %i unlocked\n"), pos);
			} else if (msg == -1) {
				printf("ML");
			}
			
			fflush(stdout);
		}
	}
}


extern char **environ;

bool exec_name(char *exec_name, char * exec_dir[], char **dup_stdout, size_t *dup_stdout_len, int *exec_ret_val, bool is_wait_child, ...) {
	pid_t pid;
	posix_spawn_file_actions_t action;
	posix_spawnattr_t attr;
	int pipefd[2];
	bool ret;
	char *path = NULL;
	
	// Check if the executable exists
	for (int i = 0; ; i++){
		if (exec_dir[i] == NULL){
			errno = ENOENT;
			return false;
		}
		asprintf(&path, "%s/%s", exec_dir[i], exec_name);
		if (access(path, X_OK) != 0) {
			free(path);
			if (errno == ENOENT){
				continue;
			} else {
				return false;
			}
		} else {
			break;
		}
	}
	
	// Setup stdout redirection if required
	posix_spawn_file_actions_init(&action);
	posix_spawnattr_init(&attr);
	
	if (dup_stdout && dup_stdout_len) {
		if (pipe(pipefd) != 0) {
			perror("pipe");
			free(path);
			return false;
		}
		posix_spawn_file_actions_addclose(&action, pipefd[0]);
		posix_spawn_file_actions_adddup2(&action, pipefd[1], STDOUT_FILENO);
		posix_spawn_file_actions_addclose(&action, pipefd[1]);
	}
	if (!is_wait_child) {
		posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF);
		sigset_t signal_mask;
		sigemptyset(&signal_mask);
		sigaddset(&signal_mask, SIGCHLD);
		posix_spawnattr_setsigdefault(&attr, &signal_mask);
	}
	
	// Prepare arguments for exec
	va_list args;
	va_start(args, is_wait_child);
	char **argv = malloc(sizeof(char *) * 256); // arbitrary large number
	int argc = 0;
	argv[argc++] = exec_name;
	char *arg;
	while ((arg = va_arg(args, char *)) != NULL) {
		argv[argc++] = arg;
	}
	argv[argc] = NULL;
	
	// Spawn the process
	if (posix_spawn(&pid, path, dup_stdout ? &action : NULL, &attr, argv, environ) != 0) {
		perror("posix_spawn");
		ret = false;
	} else if (is_wait_child) {
		if (waitpid(pid, exec_ret_val, 0) == -1) {
			perror("waitpid");
			ret = false;
		} else {
			ret = true;
		}
	} else {
		ret = true;
	}
	
	// Read from pipe if required
	if (dup_stdout && dup_stdout_len) {
		close(pipefd[1]);
		
		size_t buffer_size = 1024;
		*dup_stdout = malloc(buffer_size);
		if (*dup_stdout == NULL) {
			perror("malloc");
			close(pipefd[0]);
			return false;
		}
		
		ssize_t bytes_read;
		*dup_stdout_len = 0;
		while ((bytes_read = read(pipefd[0], *dup_stdout + *dup_stdout_len, buffer_size - *dup_stdout_len)) > 0) {
			*dup_stdout_len += bytes_read;
			if (*dup_stdout_len == buffer_size) {
				buffer_size += 1024;
				char *new_buffer = realloc(*dup_stdout, buffer_size);
				if (new_buffer == NULL) {
					perror("realloc");
					free(*dup_stdout);
					close(pipefd[0]);
					return false;
				}
				*dup_stdout = new_buffer;
			}
		}
		
		if (bytes_read == -1) {
			perror("read");
			free(*dup_stdout);
			close(pipefd[0]);
			return false;
		}
		close(pipefd[0]);
	}
	
	va_end(args);
	free(argv);
	free(path);
	if (dup_stdout && dup_stdout_len) {
		posix_spawn_file_actions_destroy(&action);
	}
	posix_spawnattr_destroy(&attr);
	
	return ret;
}
