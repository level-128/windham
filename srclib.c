#include <inttypes.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <assert.h>


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

#if NO_PRINT_ != 1
#define print(...) \
   int tmp_var = CV_VA_NUM_ARGS(__VA_ARGS__);\
   p__get_types__(__VA_ARGS__);                   \
   p__expands_args(tmp_var, __VA_ARGS__);\
   p__print__(tmp_var)
#else
#define print(...) 0
#endif


bool debug_print_error_suppress = false;

#define print_error(...) \
    if (debug_print_error_suppress){ \
	 printf("\033[1;33mSUPPRESS_ERROR: "); \
    printf(__VA_ARGS__);           \
    printf("\033[0m\n");   \
	 debug_print_error_suppress = false;\
	 } else {                    \
    printf("\033[1;31mERROR: "); \
    printf(__VA_ARGS__);           \
    printf("\033[0m\n");   \
    exit(EXIT_FAILURE);} while (false)

#define print_error_no_exit(...) \
    printf("\033[1;31mERROR: "); \
    printf(__VA_ARGS__);           \
    printf("\033[0m\n")

#define print_warning(...) \
    printf("\033[1;33mWARNING: "); \
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