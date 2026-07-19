#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/windham_const.h"

#include "aes_xts_impl.c"

#ifdef WINDHAM_PLAT_GNU_LINUX
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#endif


#define var_(x) __temp_var_at_line##x
#define var__(x) var_(x)
#define tmp_var var__(__LINE__)

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)

#define swap(x, y)				\
  do {						\
    assert(sizeof(x) == sizeof(y));		\
    unsigned char tmp_var[(signed) sizeof(x)];	\
    memcpy(tmp_var, &(y), sizeof(x));		\
    memcpy(&(y), &(x), sizeof(x));		\
    memcpy(&(x), tmp_var, sizeof(x));		\
  } while (0)

#define print_error(...)							\
  do {										\
    if (init_val->is_color_print)						\
      printf("\033[1;31m%s: ", _("ERROR"));					\
    else									\
      printf(_("ERROR: \n"));						\
    printf(__VA_ARGS__);							\
    if (init_val->is_color_print)						\
      printf("\033[0m\n");							\
    else									\
      printf("\n");								\
    windham_exit(1);								\
    WINDHAM_UNREACHABLE							\
  } while (0)


#define print_error_no_exit(...)						\
  do {										\
    if (init_val->is_color_print)						\
      printf("\033[1;31m%s: ", _("ERROR"));					\
    else									\
      printf(_("ERROR: \n"));						\
    printf(__VA_ARGS__);							\
    if (init_val->is_color_print)						\
      printf("\033[0m\n");							\
    else									\
      printf("\n");								\
  } while (0)


#define print_warning(...)							\
  do {										\
    if (init_val->is_color_print)						\
      printf("\033[1;33m%s: ", _("WARNING"));				\
    else									\
      printf(_("WARNING: \n"));						\
    printf(__VA_ARGS__);							\
    if (init_val->is_color_print)						\
      printf("\033[0m\n");							\
    else									\
      printf("\n");								\
  } while (0)

bool print_debug_enable;

#define print_debug(...)			\
  do {						\
    if (print_debug_enable) {			\
      printf(__VA_ARGS__);			\
    }						\
  } while (0)

#define print_func_vars(...)			\
  printf(__func__);				\
  printf(__VA_ARGS__);

void xor_with_len(size_t length, const uint8_t a[], const uint8_t b[], uint8_t c[]);

void print_hex_array(size_t length, const uint8_t arr[]);

int64_t is_in_list(const char * item, char * list[]);


// data
#ifndef INCL_SRCLIB
#define INCL_SRCLIB


bool is_skip_conformation;


void ask_for_conformation(const char * format, ...) {
   if (is_skip_conformation) {
      return;
   }
   // 36 non-null + 9 null = 45 total; null probability = 20%
   const char confirm_pool[] = {
      'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
      'q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5',
      '6','7','8','9',
      '\0','\0','\0','\0','\0','\0','\0','\0','\0'
   };
   char       random_str[3];
   char       complete_str[10];
   char       user_input[20];

   srand(time(NULL));

   for (int i = 0; i < 2; ++i) {
      const int index = rand() % sizeof(confirm_pool);
      random_str[i]   = confirm_pool[index];
   }
   random_str[2] = '\0';

   printf(_("CONFIRMATION REQUIRED: \n"));
   va_list args;
   va_start(args, format);
   vprintf(format, args);
   va_end(args);
   sprintf(complete_str, "YES %s", random_str);
   printf(_("\nType \"%s\" to confirm."), complete_str);
   printf("\n");


   if (fgets(user_input, sizeof(user_input), stdin) == NULL) {
      perror("fgets");
      windham_exit(1);
   };
   user_input[strcspn(user_input, "\n")] = 0;
   if (strcmp(user_input, complete_str) != 0) {
      print_error(_("User has canceled the operation."));
   }
}


// -----------------------------------------------
// independent subroutines:

extern char ** environ;

/**
 * @brief Executes a given command with options and arguments.
 *
 * This function tries to execute the specified command by searching for it in the provided
 * array of directories. It checks each directory in order until the executable is found.
 * If the executable is found, it sets up stdout redirection if required and spawns a new
 * process to execute the command. It also waits for the child process to complete if the
 * `is_wait_child` argument is set to true.
 *
 * When `dup_stdout` parameter is NULL, the stdout and stderr of the child process
 * is not redirected/captured. Conversely, when `dup_stdout` is NOT NULL, the stdout and stderr of the child
 * process is captured and made available in the buffer pointed to by the `dup_stdout` argument. If `is_wait_child`
 * is false, the function does not wait for child process to terminate rather returns immediately after spawning
 * it.
 *
 * @param exec_name The name of the executable to be executed.
 * @param exec_dir An array of directories to search for the executable, must be terminated with a NULL pointer.
 * @param dup_stdout A pointer to the destination buffer for duplicated stdout stream, or NULL if stdout is not required to be captured.
 * 	The buffer is allocated by the callee. If `is_wait_child` is false, `dup_stdout` makes no effect. If the call has failed,
 * 	`dup_stdout` will not be set.
 * @param dup_stdout_len A pointer to the size of the duplicated stdout buffer, or NULL if stdout is not required to be captured.
 * 	If `is_wait_child` is false, `dup_stdout_len` makes no effect.
 * @param exec_ret_val A pointer to store the return value of the child process, or NULL if not required.
 * @param is_wait_child Flag indicating whether to wait for the child process to complete or spawn it in detached mode.
 * @param ... Optional arguments, should be provided as (char *) type, to be passed to the executed command, terminated by a NULL argument.
 * @return True if the command was executed successfully, false otherwise, in this case, errno will be set.
 *
 * @note The `exec_name` and `exec_dir` parameters must not be NULL.
 * @note The `dup_stdout` and `dup_stdout_len` parameters are only used when stdout redirection is required.
 * @note The `is_wait_child` parameter is only used when waiting for the child process to complete is required.
 * @note The environment variable 'environ' must be defined externally.
 */
typedef enum {
   NMOBJ_exec_name_wait_child      = 1,
   NMOBJ_exec_name_dup_stdout_only = 2,
   NMOBJ_exec_name_dup_stderr_only = 4
} Exec_name_flags;

#ifdef WINDHAM_PLAT_GNU_LINUX
bool exec_name(
   char *    exec_name,
   char *    exec_dir[],
   const int fd_stdin,
   // -1 means do not redirect
   char * volatile *     dup_stdout,
   size_t *              dup_stdout_len,
   int *                 exec_ret_val,
   const Exec_name_flags _flags,
   ...) {
   pid_t                      pid;
   posix_spawn_file_actions_t action;
   posix_spawnattr_t          attr;
   int                        pipefd[2];
   bool                       ret;
   char                       path[PATH_MAX];

   // Check if the executable exists
   for (int i = 0;; i ++) {
      if (exec_dir[i] == NULL) {
         errno = ENOENT;
         return false;
      }
      sprintf(path, "%s/%s", exec_dir[i], exec_name);
      if (access(path, X_OK) != 0) {
         if (errno != ENOENT) {
            return false;
         }
      } else {
         break;
      }
   }

   // Setup stdout redirection if required
   posix_spawn_file_actions_init(&action);
   posix_spawnattr_init(&attr);

   if (dup_stdout && dup_stdout_len && _flags & NMOBJ_exec_name_wait_child) {
      if (pipe(pipefd) != 0) {
         perror("pipe");
         return false;
      }
      posix_spawn_file_actions_addclose(&action, pipefd[0]);
      if (! (_flags & NMOBJ_exec_name_dup_stderr_only)) {
         posix_spawn_file_actions_adddup2(&action, pipefd[1], STDOUT_FILENO);
      }
      if (! (_flags & NMOBJ_exec_name_dup_stdout_only)) {
         posix_spawn_file_actions_adddup2(&action, pipefd[1], STDERR_FILENO);
      }
      posix_spawn_file_actions_addclose(&action, pipefd[1]);
   }
   if (! _flags) {
      posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF);
      sigset_t signal_mask;
      sigemptyset(&signal_mask);
      sigaddset(&signal_mask, SIGCHLD);
      posix_spawnattr_setsigdefault(&attr, &signal_mask);
   }

   if (fd_stdin != -1) {
      posix_spawn_file_actions_adddup2(&action, fd_stdin, STDIN_FILENO);
   }

   // Prepare arguments for exec
   va_list args;
   va_start(args, _flags);
   char ** argv  = malloc(sizeof(char *) * 256); // arbitrary large number
   int     argc  = 0;
   argv[argc ++] = exec_name;
   char * arg;
   while ((arg = va_arg(args, char *)) != NULL) {
      argv[argc ++] = arg;
   }
   argv[argc] = NULL;

   // Spawn the process
   if (posix_spawn(
          &pid,
          path,
          dup_stdout
             ? &action
             : NULL,
          &attr,
          argv,
          environ) != 0) {
      perror("posix_spawn");
      ret = false;
   } else if (_flags) {
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
   if (dup_stdout && dup_stdout_len && _flags) {
      close(pipefd[1]);

      size_t buffer_size = 1024;
      *dup_stdout        = malloc(buffer_size);
      if (*dup_stdout == NULL) {
         perror("malloc");
         close(pipefd[0]);
         exit(1);
      }

      ssize_t bytes_read;
      *dup_stdout_len = 0;
      while ((bytes_read = read(pipefd[0], *dup_stdout + *dup_stdout_len, buffer_size - *dup_stdout_len)) > 0) {
         *dup_stdout_len += bytes_read;
         if (*dup_stdout_len == buffer_size) {
            buffer_size += 1024;
            char * new_buffer = realloc(*dup_stdout, buffer_size);
            if (new_buffer == NULL) {
               perror("realloc");
               free(*dup_stdout);
               close(pipefd[0]);
               exit(1);
            }
            *dup_stdout = new_buffer;
         }
      }

      if (bytes_read == -1) {
         perror("read");
         free(*dup_stdout);
         free(argv);
         close(pipefd[0]);
         return false;
      }
      close(pipefd[0]);
   }

   va_end(args);
   free(argv);
   if (dup_stdout && dup_stdout_len && _flags) {
      posix_spawn_file_actions_destroy(&action);
   }
   posix_spawnattr_destroy(&attr);

   return ret;
}
#else
bool exec_name(char * _, ...) {
   exit(2);
}
#endif


inline void xor_with_len(const size_t length, const uint8_t a[], const uint8_t b[], uint8_t c[]) {
   for (size_t i = 0; i < length; i ++) {
      c[i] = a[i] ^ b[i];
   }
}


void print_hex_array(const size_t length, const uint8_t arr[]) {
   for (size_t i = 0; i < length; ++i) {
      printf("%02x ", arr[i]);
   }
   printf("\n");
}


int64_t is_in_list(const char * item, char * list[]) {
   for (int64_t i = 0; list[i]; i ++) {
      if (strcmp(item, list[i]) == 0) {
         return i;
      }
   }
   return -1;
}

static bool is_string_startwith(const char * string, const char * target) {
   const size_t string_len = strlen(string);
   const size_t target_len = strlen(target);
   return string_len >= target_len && memcmp(string, target, target_len) == 0;
}


void generate_UUID_from_bytes(const unsigned char bytes[16], char uuid_str[37]) {
   sprintf(
      uuid_str,
      "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      bytes[0],
      bytes[1],
      bytes[2],
      bytes[3],
      bytes[4],
      bytes[5],
      bytes[6],
      bytes[7],
      bytes[8],
      bytes[9],
      bytes[10],
      bytes[11],
      bytes[12],
      bytes[13],
      bytes[14],
      bytes[15]);
}


bool generate_bytes_from_UUID(const char uuid_str[37], uint8_t bytes[16]) {
   bool    is_first_hex = true;
   uint8_t convert_res;
   for (int i = 0, byte_index = 0; true; i ++) {
      const char c = uuid_str[i];
      if (i == 36) {
         return true;
      }
      if (i == 8 || i == 13 || i == 18 || i == 23) {
         if (c == '-') {
            continue;
         }
         return false;
      }
      if (c >= '0' && c <= '9') {
         convert_res = c - '0';
      } else if (c >= 'a' && c <= 'f') {
         convert_res = 10 + (c - 'a');
      } else if (c >= 'A' && c <= 'F') {
         convert_res = 10 + (c - 'A');
      } else {
         return false;
      }
      bytes[byte_index] = is_first_hex
                             ? convert_res << 4
                             : bytes[byte_index] | convert_res;
      is_first_hex = ! is_first_hex;
      byte_index += is_first_hex;
   }
}


int ask_option(const char * title, ...) {
   va_list args;
   char input[3];
   int  count = 0;

   printf("%s\n", title);

   va_start(args, title);
   while (1) {
      const char * option = va_arg(args, const char *);
      if (option == NULL)
         break;
      if (count == 0) {
         printf("%d. %s (default)\n", ++count, option);
      } else {
         printf("%d. %s\n", ++count, option);
      }

   }
   va_end(args);

   printf(_("Select an option:"));

   while (true) {
      if (fgets(input, sizeof(input), stdin) == NULL) {
         perror("fgets");
         windham_exit(1);
      }
      if (input[0] == '\n') {
         input[0] = '1';
         break;
      }
      if (input[1] != '\n' ||
         !(input[0] >= '0' && input[0] <= '9')) {
         printf(_("\nError input. Select an option:"));
         while (getchar() != '\n') {}
         continue;
      }
      if (input[0] >= '1' && input[0] <= '0' + count) {
         break;
      } else {
         printf(_("\nError input. Select an option within 1 - %i:"), count);
         continue;
      }
   }
   return input[0] - '0';
}


void extract_non_digits_unit(char * input, char * output, const size_t max_len) {
   int       j             = 0;
   const int i_end         = strlen(input);
   bool      is_start_unit = false;
   for (int i = 0; i < i_end && j < (int) max_len - 1; i ++) {
      if (! is_start_unit) {
         is_start_unit = ! (isdigit(input[i]) || input[i] == '.');
         i             = i - (int) is_start_unit;
         continue;
      }
      if (input[i] == '\n') {
         input[i] = '\0';
      } else if (! isdigit(input[i])) {
         output[j ++] = input[i];
         input[i]     = '\0';
      } else {
         exit(1); // digit after unit
      }
   }
   output[j] = '\0';
}


void split_on_first_dot(const char * str, char * before, char * after) {
   const char * dot = strchr(str, '.');
   if (dot != NULL) {
      if (dot - str > (int) strlen(STRINGIFY(UINT64_MAX))) {
         exit(1); // before too long
      }
      strncpy(before, str, dot - str);
      before[dot - str] = '\0';
      if (strlen(dot + 1) > strlen(STRINGIFY(UINT64_MAX))) {
         exit(1); // after too long
      }
      strcpy(after, dot + 1);
      if (strchr(after, '.') != NULL) {
         exit(1); // more than one dot
      }
   } else {
      if (strlen(str) > strlen(STRINGIFY(UINT64_MAX))) {
         exit(1); // before too long
      }
      strcpy(before, str);
      after[0] = '0', after[1] = '\0';
   }
}


uint64_t parse_size(const char * size_str) {
   if (size_str == NULL || size_str[0] == (char) 0) {
      print_error(_("invalid size input"));
   }

   char * input = malloc(strlen(size_str) + 1);
   strcpy(input, size_str);

   char unit[4] = {0};
   extract_non_digits_unit(input, unit, 4);
   char integer_part_str[sizeof("18446744073709551615")]; // uint64_t max
   char decimal_part_str[sizeof("18446744073709551615") + 2];
   strcpy(decimal_part_str, "0.");
   split_on_first_dot(input, integer_part_str, decimal_part_str + 2);


   const uint64_t integer_part = strtoull(integer_part_str, NULL, 10);

   const double decimal_part = strtod(decimal_part_str, NULL);

   uint64_t base_multiplier;
   double   decimal_multiplier;

   if (strcmp(unit, "") == 0 || strcmp(unit, "B") == 0) {
      base_multiplier    = 1;
      decimal_multiplier = 0;
   } else if (strcmp(unit, "K") == 0 || strcmp(unit, "KB") == 0) {
      base_multiplier    = 1000;
      decimal_multiplier = 1000.0;
   } else if (strcmp(unit, "M") == 0 || strcmp(unit, "MB") == 0) {
      base_multiplier    = 1000000;
      decimal_multiplier = 1000000.0;
   } else if (strcmp(unit, "G") == 0 || strcmp(unit, "GB") == 0) {
      base_multiplier    = 1000000000;
      decimal_multiplier = 1000000000.0;
   } else if (strcmp(unit, "T") == 0 || strcmp(unit, "TB") == 0) {
      base_multiplier    = 1000000000000;
      decimal_multiplier = 1000000000000.0;
   } else if (strcmp(unit, "P") == 0 || strcmp(unit, "PB") == 0) {
      base_multiplier    = 1000000000000000;
      decimal_multiplier = 1000000000000000.0;
   } else if (strcmp(unit, "E") == 0 || strcmp(unit, "EB") == 0) {
      base_multiplier    = 1000000000000000000ULL;
      decimal_multiplier = 1000000000000000000.0;
   } else if (strcmp(unit, "Ki") == 0 || strcmp(unit, "KiB") == 0) {
      base_multiplier    = 1024;
      decimal_multiplier = 1024.0;
   } else if (strcmp(unit, "Mi") == 0 || strcmp(unit, "MiB") == 0) {
      base_multiplier    = 1048576;
      decimal_multiplier = 1048576.0;
   } else if (strcmp(unit, "Gi") == 0 || strcmp(unit, "GiB") == 0) {
      base_multiplier    = 1073741824;
      decimal_multiplier = 1073741824.0;
   } else if (strcmp(unit, "Ti") == 0 || strcmp(unit, "TiB") == 0) {
      base_multiplier    = 1099511627776;
      decimal_multiplier = 1099511627776.0;
   } else if (strcmp(unit, "Pi") == 0 || strcmp(unit, "PiB") == 0) {
      base_multiplier    = 1125899906842624;
      decimal_multiplier = 1125899906842624.0;
   } else if (strcmp(unit, "Ei") == 0 || strcmp(unit, "EiB") == 0) {
      base_multiplier    = 1152921504606846976ULL;
      decimal_multiplier = 1152921504606846976.0;
   } else if (strcmp(unit, "SEC") == 0) {
      base_multiplier    = 512;
      decimal_multiplier = 512.0;
   } else {
      print_error(
         _("Invalid input. Input without unit = bytes; supported units are: SEC(512 bytes) K M G T P and E, or Ki Mi Gi Ti Pi and "
            "Ei for IEC units. Postfix \"B\" is optional. "));
   }

   free(input);

   uint64_t bytes         = integer_part * base_multiplier;
   uint64_t decimal_bytes = (uint64_t) (decimal_part * decimal_multiplier); // round down
    return bytes + decimal_bytes;
}


/* -- Dynamic buffer (type-erased growable array) -- */

typedef struct {
    uint8_t *data;
    size_t   elem_size;
    size_t   count;
    size_t   capacity;
} DynBuf;

static void db_init(DynBuf *db, size_t elem_size) {
    db->elem_size = elem_size;
    db->count     = 0;
    db->capacity  = 16;  // initial capacity
    db->data      = malloc(elem_size * db->capacity);
    if (!db->data) { print_error(_("Out of memory")); }
}

static void db_free(DynBuf *db) {
    free(db->data);
    db->data = NULL;
    db->count = db->capacity = 0;
}

static void *db_add(DynBuf *db, const void *elem) {
    if (db->count >= db->capacity) {
        size_t new_cap = db->capacity * 2;
        uint8_t *p = realloc(db->data, db->elem_size * new_cap);
        if (!p) { print_error(_("Out of memory")); }
        db->data     = p;
        db->capacity = new_cap;
    }
    void *dst = db->data + db->count * db->elem_size;
    if (elem) memcpy(dst, elem, db->elem_size);
    db->count++;
    return dst;
}

static void *db_get(DynBuf *db, size_t index) {
    return db->data + index * db->elem_size;
}

static size_t db_count(DynBuf *db) {
    return db->count;
}

// Remove first n elements (shift left)
static void db_remove_front_n(DynBuf *db, size_t n) {
    if (n >= db->count) { db->count = 0; return; }
    size_t remaining = db->count - n;
    memmove(db->data, db->data + n * db->elem_size, remaining * db->elem_size);
    db->count = remaining;
}

// Remove element at index (shift left)
static void db_remove_at(DynBuf *db, size_t index) {
    if (index >= db->count) return;
    size_t tail = db->count - index - 1;
    if (tail > 0) {
        memmove(db->data + index * db->elem_size,
                db->data + (index + 1) * db->elem_size,
                tail * db->elem_size);
    }
    db->count--;
}

// Reset count to 0 without freeing
static void db_clear(DynBuf *db) {
    db->count = 0;
}

#endif // #ifndef INCL_SRCLIB
