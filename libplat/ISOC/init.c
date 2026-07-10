#include <locale.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "../../library/include_all_libs.c"

static int verify_unix_device(const char *path, int (*validator)(FILE*)) {
    FILE *dev = fopen(path, "rb+");
    if (!dev) return 1;

    int result = validator(dev);
    fclose(dev);
    return result;
}


static int validate_dev_null(FILE *dev) {
    char buf;
    if (fread(&buf, 1, 1, dev) != 0) {
        return 1;
    }

    const char test_data[] = "null_test";
    if (fwrite(test_data, 1, sizeof(test_data), dev) != sizeof(test_data)) {
        return 1;
    }
    fflush(dev);

    rewind(dev);
    if (fread(&buf, 1, 1, dev) != 0) {
        return 1;
    }

    return 0;
}


static int validate_dev_zero(FILE *dev) {
    unsigned char buf1[32];
    if (fread(buf1, 1, sizeof(buf1), dev) != sizeof(buf1)) {
        return 1;
    }

    if (memcmp(buf1, (unsigned char [sizeof(buf1)]){0}, sizeof(buf1)) != 0) {
        return 1;
    }

    rewind(dev);
    const char test_data[] = "zero_test";
    if (fwrite(test_data, 1, sizeof(test_data), dev) != sizeof(test_data)) {
        return 1;
    }
    fflush(dev);

    rewind(dev);
    if (fread(buf1, 1, sizeof(buf1), dev) != sizeof(buf1)) {
        return 1;
    }

    if (memcmp(buf1, (unsigned char [sizeof(buf1)]){0}, sizeof(buf1)) != 0) {
        return 1;
    }

    return 0;
}

bool contains_utf_ic(const char *s){
    if (s == NULL) {
        return false;
    }

    size_t len = strlen(s);
    if (len < 3) {
        return false;
    }

    for (size_t i = 0; i <= len - 3; ++i) {
        if ((s[i] == 'u' || s[i] == 'U') &&
            (s[i+1] == 't' || s[i+1] == 'T') &&
            (s[i+2] == 'f' || s[i+2] == 'F'))
        {
            return true;
        }
    }

    return false;
}

void frontend_init(int argc, char *argv[]){

    setvbuf(stdin, NULL, _IONBF, 0);

    // no auto exec aux under ISO C
    init_val->is_secure_env = false; 
    init_val->is_shebang = false;
    init_val->is_random_number_trustworthy = EMOBJ_RANDOM_NUMBER_INTERNAL;

    init_val->initial_internal_entropy_source.clock = clock();
    if (init_val->initial_internal_entropy_source.clock == (clock_t)(-1)){
        // no CPU time, under embedded system?
        init_val->is_random_number_trustworthy = EMOBJ_RANDOM_NUMBER_WEAK;
    }
    if (CLOCKS_PER_SEC < 1000){
        init_val->is_random_number_trustworthy = EMOBJ_RANDOM_NUMBER_WEAK;
    }
    if (timespec_get(
        &init_val->initial_internal_entropy_source.time, 
        TIME_UTC) != TIME_UTC){
            // system has no timer, we think the entropy source cannot be trusted.
            init_val->is_random_number_trustworthy = EMOBJ_RANDOM_NUMBER_WEAK;
    }
    else {
        struct timespec ts_start;
        double ts_res;
#if (__STDC_VERSION__ >= 202311L)

        timespec_getres(&ts_start, TIME_UTC);
        ts_res = ts_start.tv_sec * 1000000000.0 + ts_start.tv_nsec;
#else
        struct timespec ts_end;
        timespec_get(&ts_start, TIME_UTC);
        while (1)
        {
            timespec_get(&ts_end, TIME_UTC);
            if (ts_end.tv_sec > ts_start.tv_sec || ts_end.tv_nsec != ts_start.tv_nsec)
            {
                ts_res = (ts_end.tv_sec - ts_start.tv_sec) * 1000000000.0 + (ts_end.tv_nsec - ts_start.tv_nsec);
                break;
            }
        }
#endif
        if (ts_res > 1000000) {
            // system timer has low res.
            init_val->is_random_number_trustworthy = EMOBJ_RANDOM_NUMBER_WEAK;
        }
    }

    char * locale_str = setlocale(LC_ALL, "");
    init_val->is_color_print = contains_utf_ic(locale_str);

    if (verify_unix_device("/dev/null", validate_dev_null) &&
        verify_unix_device("/dev/zero", validate_dev_zero)){
            init_val->is_random_number_trustworthy = EMOBJ_RANDOM_NUMBER_SYSTEM;
        }
}