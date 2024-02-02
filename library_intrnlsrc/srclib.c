#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <spawn.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <string.h>
#include <linux/limits.h>
#include <time.h>
#include <stddef.h>
#include <unistd.h>

#ifndef _ // no GNU gettext
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
bool print_verbose;

#define print(...) \
   if (print_enable){                \
   int tmp_var = CV_VA_NUM_ARGS(__VA_ARGS__);\
   p__get_types__(__VA_ARGS__);                   \
   p__expands_args(tmp_var, __VA_ARGS__);\
   p__print__(tmp_var);} while(0)


int debug_print_error_suppress;

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

#define BOOL_ADDER(a) bool a
#define COMMA_SEPARATOR ,

#define ARGFLG_1(a) BOOL_ADDER(a)
#define ARGFLG_2(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_1(__VA_ARGS__)
#define ARGFLG_3(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_2(__VA_ARGS__)
#define ARGFLG_4(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_3(__VA_ARGS__)
#define ARGFLG_5(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_4(__VA_ARGS__)
#define ARGFLG_6(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_5(__VA_ARGS__)
#define ARGFLG_7(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_6(__VA_ARGS__)
#define ARGFLG_8(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_7(__VA_ARGS__)
#define ARGFLG_9(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_8(__VA_ARGS__)
#define ARGFLG_10(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_9(__VA_ARGS__)
#define ARGFLG_11(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_10(__VA_ARGS__)
#define ARGFLG_12(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_11(__VA_ARGS__)
#define ARGFLG_13(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_12(__VA_ARGS__)
#define ARGFLG_14(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_13(__VA_ARGS__)
#define ARGFLG_15(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_14(__VA_ARGS__)
#define ARGFLG_16(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_15(__VA_ARGS__)
#define ARGFLG_17(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_16(__VA_ARGS__)
#define ARGFLG_18(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_17(__VA_ARGS__)
#define ARGFLG_19(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_18(__VA_ARGS__)
#define ARGFLG_20(a, ...) BOOL_ADDER(a) COMMA_SEPARATOR ARGFLG_19(__VA_ARGS__)

#define ARGFLG_N(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,N,...) __attribute__((unused)) BOOL_DEL_t _, ARGFLG_##N

#define ARGFLG(...) ARGFLG_N(__VA_ARGS__,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1)(__VA_ARGS__)  , __attribute__((unused)) BOOL_DEL_END_t _$



static void xor_with_len(size_t length, const uint8_t a[length], const uint8_t b[length], uint8_t c[length]);

bool exec_name(char *exec_name, char * exec_dir[], char **dup_stdout, size_t *dup_stdout_len, int *exec_ret_val, bool is_wait_child, ...);

void print_hex_array(size_t length, const uint8_t arr[length]);

int64_t is_in_list(char * item, char * list[]);

void print_ptr_poz(int pos, int msg, int max_poz);

// data
#ifndef INCL_SRCLIB
#define INCL_SRCLIB

typedef enum {
	T_INT,
	T_DOUBLE,
	T_CHAR,
	T_PTR,
	T_BOOL,
} TYPE_T;

__attribute__((unused)) typedef struct {
	void * tmp_var[0];
} BOOL_DEL_t;

__attribute__((unused)) typedef struct {
	void * tmp_var[0];
} BOOL_DEL_END_t;

__attribute__((unused)) BOOL_DEL_t BOOL_DEL_START;

__attribute__((unused)) BOOL_DEL_END_t BOOL_DEL_END;

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

bool is_skip_conformation;

void ask_for_conformation(const char * format, ...) {
	if (is_skip_conformation) {
		return;
	}
	const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char random_str[4];
	char complete_str[10];
	char user_input[20];
	
	srand(time(NULL)); // NOLINT(*-msc51-cpp)
	
	for (int i = 0; i < 3; ++i) {
		const int index = rand() % 64; // NOLINT(*-msc50-cpp)
		random_str[i] = base64_chars[index];
	}
	random_str[3] = '\0';
	
	printf("\033[1;33m%s\n", _("CONFORMATION REQUIRED: "));
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	sprintf(complete_str, "YES %s", random_str);
	printf(_("\nType \"%s\" to confirm."), complete_str);
	printf(" \033[0m\n");
	
	
	fgets(user_input, sizeof(user_input), stdin);
	user_input[strcspn(user_input, "\n")] = 0;
	if (strcmp(user_input, complete_str) != 0) {
		print_error(_("User has canceled the operation."));
	}
}

// -----------------------------------------------
// independent subroutines:

extern char **environ;

/**
 * @brief Executes a given command with options and arguments.
 *
 * This function tries to execute the specified command by searching for it in the provided
 * array of directories. It checks each directory in order until the executable is found.
 * If the executable is found, it sets up stdout redirection if required and spawns a new
 * process to execute the command. It also waits for the child process to complete if the
 * `is_wait_child` argument is set to true.
 *
 * When `dup_stdout` parameter is NULL, the stdout of the child process
 * is not redirected/captured. Conversely, when `dup_stdout` is NOT NULL, the stdout of the child
 * process is captured and made available in the buffer pointed to by the `dup_stdout` argument. If `is_wait_child`
 * is false, the function does not wait for child process to terminate rather returns immediately after spawning
 * it.
 *
 * @param exec_name The name of the executable to be executed.
 * @param exec_dir An array of directories to search for the executable.
 * @param dup_stdout A pointer to the destination buffer for duplicated stdout stream, or NULL if stdout is not required to be captured.
 * @param dup_stdout_len A pointer to the size of the duplicated stdout buffer, or NULL if stdout is not required to be captured.
 * @param exec_ret_val A pointer to store the return value of the child process, or NULL if not required.
 * @param is_wait_child Flag indicating whether to wait for the child process to complete or spawn it in detached mode.
 * @param ... Optional arguments to be passed to the executed command, terminated by a NULL argument.
 * @return True if the command was executed successfully, false otherwise.
 *
 * @note The `exec_name` and `exec_dir` parameters must not be NULL.
 * @note The `exec_dir` array must be terminated with a NULL pointer.
 * @note The `dup_stdout` and `dup_stdout_len` parameters are only used when stdout redirection is required.
 * @note The `is_wait_child` parameter is only used when waiting for the child process to complete is required.
 * @note The `exec_ret_val` parameter is only used when storing the return value of the child process is required.
 * @note The optional arguments should be provided as (char *) type, terminated by a NULL argument.
 * @note The environment variable 'environ' must be defined externally.
 */
bool exec_name(char *exec_name, char * exec_dir[], char **dup_stdout, size_t *dup_stdout_len, int *exec_ret_val, bool is_wait_child, ...) {
	pid_t pid;
	posix_spawn_file_actions_t action;
	posix_spawnattr_t attr;
	int pipefd[2];
	bool ret;
	char path[PATH_MAX];
	
	// Check if the executable exists
	for (int i = 0; ; i++){
		if (exec_dir[i] == NULL){
			errno = ENOENT;
			return false;
		}
		sprintf(path, "%s/%s", exec_dir[i], exec_name);
		if (access(path, X_OK) != 0) {
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
			return false;
		}
		posix_spawn_file_actions_addclose(&action, pipefd[0]);
		posix_spawn_file_actions_adddup2(&action, pipefd[1], STDOUT_FILENO);
		posix_spawn_file_actions_adddup2(&action, pipefd[1], STDERR_FILENO);
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
	if (dup_stdout && dup_stdout_len) {
		posix_spawn_file_actions_destroy(&action);
	}
	posix_spawnattr_destroy(&attr);
	
	return ret;
}

void xor_with_len(size_t length, const uint8_t a[length], const uint8_t b[length], uint8_t c[length]) {
	for (size_t i = 0; i < length; i++) {
		c[i] = a[i] ^ b[i];
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

__attribute__((unused)) void print_list(char * list[]) {
	for (int i = 0; list[i]; i++) {
		printf(" \"%s\"", list[i]);
	}
}

void print_ptr_poz(int pos, int msg, int max_poz) {
	if (print_verbose) {
		if (pos == -1) {
			printf(_("Unlock Progress for each keyslot:\n"));
			printf("\nSlot:     ");
			for (int i = 0; i < max_poz; i++) {
				printf("%i       ", i);
			}
			printf("\nProgress: ");
			for (int i = 0; i < max_poz; i++) {
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

void generate_UUID_from_bytes(const unsigned char bytes[16], char uuid_str[37]) {
	sprintf(uuid_str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	        bytes[0], bytes[1], bytes[2], bytes[3],
	        bytes[4], bytes[5], bytes[6], bytes[7],
	        bytes[8], bytes[9], bytes[10], bytes[11],
	        bytes[12], bytes[13], bytes[14], bytes[15]);
}

#endif // #ifndef INCL_SRCLIB